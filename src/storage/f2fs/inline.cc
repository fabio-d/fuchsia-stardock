// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <dirent.h>

#include "src/storage/f2fs/f2fs.h"

namespace f2fs {

uint32_t Dir::MaxInlineDentry() const {
  return MaxInlineData() * kBitsPerByte / ((kSizeOfDirEntry + kDentrySlotLen) * kBitsPerByte + 1);
}

uint8_t *Dir::InlineDentryBitmap(Page *page) {
  Node *rn = page->GetAddress<Node>();
  Inode &ri = rn->i;
  return reinterpret_cast<uint8_t *>(
      &ri.i_addr[GetExtraISize() / sizeof(uint32_t) + kInlineStartOffset]);
}

uint64_t Dir::InlineDentryBitmapSize() const {
  return (MaxInlineDentry() + kBitsPerByte - 1) / kBitsPerByte;
}

DirEntry *Dir::InlineDentryArray(Page *page) {
  uint8_t *base = InlineDentryBitmap(page);
  uint32_t reserved = MaxInlineData() - MaxInlineDentry() * (kSizeOfDirEntry + kDentrySlotLen);
  return reinterpret_cast<DirEntry *>(base + reserved);
}

uint8_t (*Dir::InlineDentryFilenameArray(Page *page))[kDentrySlotLen] {
  uint8_t *base = InlineDentryBitmap(page);
  uint32_t reserved = MaxInlineData() - MaxInlineDentry() * kDentrySlotLen;
  return reinterpret_cast<uint8_t(*)[kDentrySlotLen]>(base + reserved);
}

DirEntry *Dir::FindInInlineDir(std::string_view name, fbl::RefPtr<Page> *res_page) {
  fbl::RefPtr<NodePage> ipage = nullptr;
  if (zx_status_t ret = Vfs()->GetNodeManager().GetNodePage(Ino(), &ipage); ret != ZX_OK)
    return nullptr;
  *res_page = std::move(ipage);
  f2fs_hash_t namehash = DentryHash(name);

  for (uint32_t bit_pos = 0; bit_pos < MaxInlineDentry();) {
    bit_pos = FindNextBit(InlineDentryBitmap((*res_page).get()), MaxInlineDentry(), bit_pos);
    if (bit_pos >= MaxInlineDentry()) {
      break;
    }

    DirEntry *de = &InlineDentryArray((*res_page).get())[bit_pos];
    if (EarlyMatchName(name, namehash, *de)) {
      if (!memcmp(InlineDentryFilenameArray((*res_page).get())[bit_pos], name.data(),
                  name.length())) {
        (*res_page)->Unlock();

#ifdef __Fuchsia__
        if (de != nullptr) {
          Vfs()->GetDirEntryCache().UpdateDirEntry(Ino(), name, *de,
                                                   kCachedInlineDirEntryPageIndex);
        }
#endif  // __Fuchsia__
        return de;
      }
    }

    // For the most part, it should be a bug when name_len is zero.
    // We stop here for figuring out where the bugs are occurred.
#if 0  // porting needed
    // f2fs_bug_on(F2FS_P_SB(node_page), !de->name_len);
#else
    ZX_ASSERT(de->name_len > 0);
#endif

    bit_pos += GetDentrySlots(LeToCpu(de->name_len));
  }

  Page::PutPage(std::move(*res_page), true);
  return nullptr;
}

DirEntry *Dir::ParentInlineDir(fbl::RefPtr<Page> *out) {
  fbl::RefPtr<NodePage> ipage;
  if (zx_status_t ret = Vfs()->GetNodeManager().GetNodePage(Ino(), &ipage); ret != ZX_OK) {
    return nullptr;
  }

  DirEntry *de = &InlineDentryArray(ipage.get())[1];
  ipage->Unlock();
  *out = std::move(ipage);
  return de;
}

zx_status_t Dir::MakeEmptyInlineDir(VnodeF2fs *vnode) {
  fbl::RefPtr<NodePage> ipage;

  if (zx_status_t err = Vfs()->GetNodeManager().GetNodePage(vnode->Ino(), &ipage); err != ZX_OK)
    return err;

  DirEntry *de = &InlineDentryArray(&(*ipage))[0];
  de->name_len = CpuToLe(static_cast<uint16_t>(1));
  de->hash_code = 0;
  de->ino = CpuToLe(vnode->Ino());
  memcpy(InlineDentryFilenameArray(&(*ipage))[0], ".", 1);
  SetDeType(de, vnode);

  de = &InlineDentryArray(&(*ipage))[1];
  de->hash_code = 0;
  de->name_len = CpuToLe(static_cast<uint16_t>(2));
  de->ino = CpuToLe(Ino());
  memcpy(InlineDentryFilenameArray(&(*ipage))[1], "..", 2);
  SetDeType(de, vnode);

  TestAndSetBit(0, InlineDentryBitmap(&(*ipage)));
  TestAndSetBit(1, InlineDentryBitmap(&(*ipage)));

  ipage->SetDirty();

  if (vnode->GetSize() < vnode->MaxInlineData()) {
    vnode->SetSize(vnode->MaxInlineData());
    vnode->SetFlag(InodeInfoFlag::kUpdateDir);
  }

  Page::PutPage(std::move(ipage), true);

  return ZX_OK;
}

unsigned int Dir::RoomInInlineDir(Page *ipage, int slots) {
  int bit_start = 0;

  while (true) {
    int zero_start = FindNextZeroBit(InlineDentryBitmap(ipage), MaxInlineDentry(), bit_start);
    if (zero_start >= static_cast<int>(MaxInlineDentry()))
      return MaxInlineDentry();

    int zero_end = FindNextBit(InlineDentryBitmap(ipage), MaxInlineDentry(), zero_start);
    if (zero_end - zero_start >= slots)
      return zero_start;

    bit_start = zero_end + 1;

    if (zero_end + 1 >= static_cast<int>(MaxInlineDentry())) {
      return MaxInlineDentry();
    }
  }
}

zx_status_t Dir::ConvertInlineDir() {
  fbl::RefPtr<Page> page;
  if (zx_status_t ret = GrabCachePage(0, &page); ret != ZX_OK) {
    return ret;
  }

  DnodeOfData dn;
  NodeManager::SetNewDnode(dn, this, nullptr, nullptr, 0);
  if (zx_status_t err = Vfs()->GetNodeManager().GetDnodeOfData(dn, 0, 0); err != ZX_OK) {
    return err;
  }

  if (dn.data_blkaddr == kNullAddr) {
    if (zx_status_t err = ReserveNewBlock(*dn.node_page, dn.ofs_in_node); err != ZX_OK) {
      F2fsPutDnode(&dn);
      Page::PutPage(std::move(page), true);
      return err;
    }
    dn.data_blkaddr = kNewAddr;
  }

  page->WaitOnWriteback();
  page->ZeroUserSegment(0, kPageSize);

  DentryBlock *dentry_blk = page->GetAddress<DentryBlock>();

  Page *ipage = dn.inode_page.get();
  // copy data from inline dentry block to new dentry block
  memcpy(dentry_blk->dentry_bitmap, InlineDentryBitmap(ipage), InlineDentryBitmapSize());
  memcpy(dentry_blk->dentry, InlineDentryArray(ipage), sizeof(DirEntry) * MaxInlineDentry());
  memcpy(dentry_blk->filename, InlineDentryFilenameArray(ipage), MaxInlineDentry() * kNameLen);

#if 0  // porting needed
//   kunmap(page);
#endif
  page->SetUptodate();
  page->SetDirty();
  // TODO: Use writeback() while keeping the lock
  if (page->ClearDirtyForIo(true)) {
    page->SetWriteback();
    fbl::RefPtr<Page> written_page = page;
    Vfs()->GetSegmentManager().WriteDataPage(this, std::move(written_page), dn.nid, dn.ofs_in_node,
                                             dn.data_blkaddr, &dn.data_blkaddr);
    SetDataBlkaddr(*dn.node_page, dn.ofs_in_node, dn.data_blkaddr);
    UpdateExtentCache(dn.data_blkaddr, 0);
    UpdateVersion();
  }
  // clear inline dir and flag after data writeback
  ipage->WaitOnWriteback();
  ipage->ZeroUserSegment(InlineDataOffset(), InlineDataOffset() + MaxInlineData());
  ClearFlag(InodeInfoFlag::kInlineDentry);

  if (GetSize() < kPageSize) {
    SetSize(kPageSize);
    SetFlag(InodeInfoFlag::kUpdateDir);
  }

  UpdateInode(ipage);
#if 0  // porting needed
  // stat_dec_inline_inode(dir);
#endif
  F2fsPutDnode(&dn);
  Page::PutPage(std::move(page), true);
  return ZX_OK;
}

zx_status_t Dir::AddInlineEntry(std::string_view name, VnodeF2fs *vnode, bool *is_converted) {
  *is_converted = false;

  f2fs_hash_t name_hash = DentryHash(name);

  fbl::RefPtr<NodePage> ipage;
  if (zx_status_t err = Vfs()->GetNodeManager().GetNodePage(Ino(), &ipage); err != ZX_OK) {
    return err;
  }

  int slots = GetDentrySlots(static_cast<uint16_t>(name.length()));
  unsigned int bit_pos = RoomInInlineDir(ipage.get(), slots);
  if (bit_pos >= MaxInlineDentry()) {
    Page::PutPage(std::move(ipage), true);
    ZX_ASSERT(ConvertInlineDir() == ZX_OK);

    *is_converted = true;
    return ZX_OK;
  }

  ipage->WaitOnWriteback();

#if 0  // porting needed
  // down_write(&F2FS_I(inode)->i_sem);
#endif

  if (zx_status_t err = InitInodeMetadata(vnode); err != ZX_OK) {
#if 0  // porting needed
    // up_write(&F2FS_I(inode)->i_sem);
#endif

    if (TestFlag(InodeInfoFlag::kUpdateDir)) {
      UpdateInode(ipage.get());
      ClearFlag(InodeInfoFlag::kUpdateDir);
    }
    Page::PutPage(std::move(ipage), true);
    return err;
  }

  DirEntry *de = &InlineDentryArray(ipage.get())[bit_pos];
  de->hash_code = name_hash;
  de->name_len = static_cast<uint16_t>(CpuToLe(name.length()));
  memcpy(InlineDentryFilenameArray(ipage.get())[bit_pos], name.data(), name.length());
  de->ino = CpuToLe(vnode->Ino());
  SetDeType(de, vnode);
  for (int i = 0; i < slots; ++i) {
    TestAndSetBit(bit_pos + i, InlineDentryBitmap(ipage.get()));
  }

#ifdef __Fuchsia__
  if (de != nullptr) {
    Vfs()->GetDirEntryCache().UpdateDirEntry(Ino(), name, *de, kCachedInlineDirEntryPageIndex);
  }
#endif  // __Fuchsia__

  ipage->SetDirty();
  UpdateParentMetadata(vnode, 0);
  vnode->WriteInode();
  UpdateInode(ipage.get());

#if 0  // porting needed
  // up_write(&F2FS_I(inode)->i_sem);
#endif

  if (TestFlag(InodeInfoFlag::kUpdateDir)) {
    ClearFlag(InodeInfoFlag::kUpdateDir);
  }

  Page::PutPage(std::move(ipage), true);
  return ZX_OK;
}

void Dir::DeleteInlineEntry(DirEntry *dentry, Page *page, VnodeF2fs *vnode) {
  page->Lock();
  page->WaitOnWriteback();

  unsigned int bit_pos = static_cast<uint32_t>(dentry - InlineDentryArray(page));
  int slots = GetDentrySlots(LeToCpu(dentry->name_len));
  for (int i = 0; i < slots; ++i)
    TestAndClearBit(bit_pos + i, InlineDentryBitmap(page));

  page->SetDirty();

#ifdef __Fuchsia__
  std::string_view remove_name(reinterpret_cast<char *>(InlineDentryFilenameArray(page)[bit_pos]),
                               LeToCpu(dentry->name_len));

  Vfs()->GetDirEntryCache().RemoveDirEntry(Ino(), remove_name);
#endif  // __Fuchsia__

  timespec cur_time;
  clock_gettime(CLOCK_REALTIME, &cur_time);
  SetCTime(cur_time);
  SetMTime(cur_time);

  if (vnode && vnode->IsDir()) {
    DropNlink();
  }

  if (vnode) {
    clock_gettime(CLOCK_REALTIME, &cur_time);
    SetCTime(cur_time);
    SetMTime(cur_time);
    vnode->SetCTime(cur_time);
    vnode->DropNlink();
    if (vnode->IsDir()) {
      vnode->DropNlink();
      vnode->InitSize();
    }
    vnode->WriteInode(false);
    if (vnode->GetNlink() == 0) {
      Vfs()->AddOrphanInode(vnode);
    }
  }
  UpdateInode(page);
  page->Unlock();
}

bool Dir::IsEmptyInlineDir() {
  fbl::RefPtr<NodePage> ipage;

  if (zx_status_t err = Vfs()->GetNodeManager().GetNodePage(Ino(), &ipage); err != ZX_OK)
    return false;

  unsigned int bit_pos = 2;
  bit_pos = FindNextBit(InlineDentryBitmap(ipage.get()), MaxInlineDentry(), bit_pos);

  Page::PutPage(std::move(ipage), true);

  if (bit_pos < MaxInlineDentry()) {
    return false;
  }

  return true;
}

zx_status_t Dir::ReadInlineDir(fs::VdirCookie *cookie, void *dirents, size_t len,
                               size_t *out_actual) {
  fs::DirentFiller df(dirents, len);
  uint64_t *pos_cookie = reinterpret_cast<uint64_t *>(cookie);

  if (*pos_cookie == MaxInlineDentry()) {
    *out_actual = 0;
    return ZX_OK;
  }

  fbl::RefPtr<NodePage> ipage;

  if (zx_status_t err = Vfs()->GetNodeManager().GetNodePage(Ino(), &ipage); err != ZX_OK)
    return err;

  const unsigned char *types = kFiletypeTable;
  uint32_t bit_pos = *pos_cookie % MaxInlineDentry();

  while (bit_pos < MaxInlineDentry()) {
    bit_pos = FindNextBit(InlineDentryBitmap(ipage.get()), MaxInlineDentry(), bit_pos);
    if (bit_pos >= MaxInlineDentry()) {
      break;
    }

    DirEntry *de = &InlineDentryArray(ipage.get())[bit_pos];
    unsigned char d_type = DT_UNKNOWN;
    if (de->file_type < static_cast<uint8_t>(FileType::kFtMax))
      d_type = types[de->file_type];

    std::string_view name(reinterpret_cast<char *>(InlineDentryFilenameArray(ipage.get())[bit_pos]),
                          LeToCpu(de->name_len));

    if (de->ino && name != "..") {
      if (zx_status_t ret = df.Next(name, d_type, LeToCpu(de->ino)); ret != ZX_OK) {
        *pos_cookie = bit_pos;
        Page::PutPage(std::move(ipage), true);

        *out_actual = df.BytesFilled();
        return ZX_OK;
      }
    }

    bit_pos += GetDentrySlots(LeToCpu(de->name_len));
  }

  *pos_cookie = MaxInlineDentry();
  Page::PutPage(std::move(ipage), true);

  *out_actual = df.BytesFilled();

  return ZX_OK;
}

uint8_t *File::InlineDataPtr(Page *page) {
  Node *rn = page->GetAddress<Node>();
  Inode &ri = rn->i;
  return reinterpret_cast<uint8_t *>(
      &ri.i_addr[GetExtraISize() / sizeof(uint32_t) + kInlineStartOffset]);
}

zx_status_t File::ReadInline(void *data, size_t len, size_t off, size_t *out_actual) {
  fbl::RefPtr<NodePage> inline_page;
  if (zx_status_t ret = Vfs()->GetNodeManager().GetNodePage(Ino(), &inline_page); ret != ZX_OK) {
    return ret;
  }

  uint8_t *inline_data = InlineDataPtr(inline_page.get());
  size_t cur_len = std::min(len, GetSize() - off);
  memcpy(static_cast<uint8_t *>(data), inline_data + off, cur_len);

  Page::PutPage(std::move(inline_page), true);

  *out_actual = cur_len;

  return ZX_OK;
}

zx_status_t File::ConvertInlineData() {
  fbl::RefPtr<Page> page;
  if (zx_status_t ret = GrabCachePage(0, &page); ret != ZX_OK) {
    return ret;
  }

  DnodeOfData dn;
  NodeManager::SetNewDnode(dn, this, nullptr, nullptr, 0);
  if (zx_status_t err = Vfs()->GetNodeManager().GetDnodeOfData(dn, 0, 0); err != ZX_OK) {
    return err;
  }

  if (dn.data_blkaddr == kNullAddr) {
    if (zx_status_t err = ReserveNewBlock(*dn.node_page, dn.ofs_in_node); err != ZX_OK) {
      F2fsPutDnode(&dn);
      Page::PutPage(std::move(page), true);
      return err;
    }
  }

  page->WaitOnWriteback();
  page->ZeroUserSegment(0, kPageSize);

  Page *ipage = dn.inode_page.get();
  uint8_t *inline_data = InlineDataPtr(ipage);
  memcpy(page->GetAddress(), inline_data, GetSize());

  page->SetDirty();

  ipage->WaitOnWriteback();
  ipage->ZeroUserSegment(InlineDataOffset(), InlineDataOffset() + MaxInlineData());
  ClearFlag(InodeInfoFlag::kInlineData);

  UpdateInode(ipage);

  F2fsPutDnode(&dn);
  Page::PutPage(std::move(page), true);
  return ZX_OK;
}

zx_status_t File::WriteInline(const void *data, size_t len, size_t offset, size_t *out_actual) {
  fbl::RefPtr<NodePage> inline_page;
  if (zx_status_t ret = Vfs()->GetNodeManager().GetNodePage(Ino(), &inline_page); ret != ZX_OK) {
    return ret;
  }

  inline_page->WaitOnWriteback();

  uint8_t *inline_data = InlineDataPtr(inline_page.get());
  memcpy(inline_data + offset, static_cast<const uint8_t *>(data), len);

  SetSize(std::max(static_cast<size_t>(GetSize()), offset + len));
  SetFlag(InodeInfoFlag::kDataExist);
  inline_page->SetDirty();
  Page::PutPage(std::move(inline_page), true);

  timespec cur_time;
  clock_gettime(CLOCK_REALTIME, &cur_time);
  SetCTime(cur_time);
  SetMTime(cur_time);
  MarkInodeDirty();

  *out_actual = len;

  return ZX_OK;
}

zx_status_t File::TruncateInline(size_t len) {
  fbl::RefPtr<NodePage> inline_page;
  if (zx_status_t ret = Vfs()->GetNodeManager().GetNodePage(Ino(), &inline_page); ret != ZX_OK) {
    return ret;
  }

  inline_page->WaitOnWriteback();

  uint8_t *inline_data = InlineDataPtr(inline_page.get());
  size_t size_diff = (len > GetSize()) ? (len - GetSize()) : (GetSize() - len);
  memset(inline_data + ((len > GetSize()) ? GetSize() : len), 0, size_diff);

  SetSize(len);
  if (GetSize() == 0) {
    ClearFlag(InodeInfoFlag::kDataExist);
  }

  inline_page->SetDirty();
  Page::PutPage(std::move(inline_page), true);

  timespec cur_time;
  clock_gettime(CLOCK_REALTIME, &cur_time);
  SetCTime(cur_time);
  SetMTime(cur_time);
  MarkInodeDirty();

  return ZX_OK;
}

}  // namespace f2fs
