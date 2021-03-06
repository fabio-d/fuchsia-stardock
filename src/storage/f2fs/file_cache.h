// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_STORAGE_F2FS_FILE_CACHE_H_
#define SRC_STORAGE_F2FS_FILE_CACHE_H_

#include <safemath/checked_math.h>
#include <storage/buffer/block_buffer.h>

namespace f2fs {

class F2fs;
class VnodeF2fs;
class FileCache;

enum class PageFlag {
  kPageUptodate = 0,  // It is uptodate. No need to read blocks from disk.
  kPageDirty,         // It needs to be written out.
  kPageWriteback,     // It is under writeback.
  kPageLocked,        // It is locked. Wait for it to be unlocked.
  kPageAlloc,         // It has a valid Page::vmo_.
  kPageMapped,        // It has a valid mapping to the address space.
  kPageActive,        // It is being referenced.
  // TODO: Clear |kPageMmapped| when all mmaped areas are unmapped.
  kPageMmapped,  // It is mmapped. Once set, it remains regardless of munmap.
  kPageFlagSize = 8,
};

constexpr pgoff_t kPgOffMax = std::numeric_limits<pgoff_t>::max();
// TODO: Once f2fs can get hints about memory pressure, remove it.
// Now, the maximum allowable memory for dirty data pages is 200MiB
constexpr int kMaxDirtyDataPages = 51200;

// It defines a writeback operation.
struct WritebackOperation {
  pgoff_t start = 0;  // All dirty Pages within the range of [start, end) are subject to writeback.
  pgoff_t end = kPgOffMax;
  pgoff_t to_write = kPgOffMax;  // The number of dirty Pages to be written.
  bool bSync = false;  // If true, FileCache::Writeback() waits for all dirty/writeback Pages to be
                       // flushed in that vnode.
  bool bReleasePages =
      true;  // If true, it releases clean Pages while traversing FileCache::page_tree_.
  VnodeCallback if_vnode =
      nullptr;  // If set, if_vnode() determines which vnodes are subject to writeback.
  PageCallback if_page =
      nullptr;  // If set, if_page() determines which Pages are subject to writeback.
};

template <typename T, bool EnableAdoptionValidator = ZX_DEBUG_ASSERT_IMPLEMENTED>
class PageRefCounted : public fs::VnodeRefCounted<T> {
 public:
  PageRefCounted(const Page &) = delete;
  PageRefCounted &operator=(const PageRefCounted &) = delete;
  PageRefCounted(const PageRefCounted &&) = delete;
  PageRefCounted &operator=(const PageRefCounted &&) = delete;
  using ::fbl::internal::RefCountedBase<EnableAdoptionValidator>::IsLastReference;

 protected:
  constexpr PageRefCounted() = default;
  ~PageRefCounted() = default;
};

class Page : public PageRefCounted<Page>,
             public fbl::Recyclable<Page>,
             public fbl::WAVLTreeContainable<Page *> {
 public:
  Page() = delete;
  Page(FileCache *file_cache, pgoff_t index);
  Page(const Page &) = delete;
  Page &operator=(const Page &) = delete;
  Page(const Page &&) = delete;
  Page &operator=(const Page &&) = delete;
  virtual ~Page();

  void fbl_recycle() { RecyclePage(); }

  pgoff_t GetKey() const { return index_; }
  pgoff_t GetIndex() const { return GetKey(); }
  VnodeF2fs &GetVnode() const;
  FileCache &GetFileCache() const;
  // To get a Page, f2fs should call FileCache::GetPage() or FileCache::FindPage() that
  // internally calls Page::GetPage(). It allocates a discardable |vmo_| and commits a page
  // if IsAllocated() is false. Then, it creates a mapping for |vmo_| to allow the access to
  // |vmo_| using a virtual address if IsMapped() is false. Finally, it requests ZX_VMO_OP_TRY_LOCK
  // to prevent the page of |vmo_| from being decommitted until there are one or more references. If
  // it fails, it means the kernel has decommitted the page of |vmo_| due to memory pressure,
  // and thus it commits a page to |vmo_| and requests ZX_VMO_OP_TRY_LOCK again.
  zx_status_t GetPage(bool need_vmo_lock);
  // f2fs should unlock a Page when it got the Page from FileCache::GetPage().
  // It unlocks |this| and resets a reference. When |unlock| is set to false, it just resets the
  // reference.
  static void PutPage(fbl::RefPtr<Page> &&page, bool unlock);
  zx_status_t VmoOpUnlock();
  zx_status_t VmoOpLock(bool commit = false);
  template <typename T = void>
  T *GetAddress() const {
    // TODO: |address_| needs to be atomically mapped in a on-demand manner.
    ZX_DEBUG_ASSERT(IsMapped());
    return reinterpret_cast<T *>(address_);
  }

  bool IsUptodate() const { return TestFlag(PageFlag::kPageUptodate); }
  bool IsDirty() const { return TestFlag(PageFlag::kPageDirty); }
  bool IsWriteback() const { return TestFlag(PageFlag::kPageWriteback); }
  bool IsLocked() const { return TestFlag(PageFlag::kPageLocked); }
  bool IsAllocated() const { return TestFlag(PageFlag::kPageAlloc); }
  bool IsMapped() const { return TestFlag(PageFlag::kPageMapped); }
  bool IsActive() const { return TestFlag(PageFlag::kPageActive); }
  bool IsMmapped() const { return TestFlag(PageFlag::kPageMmapped); }

  void ClearMapped() { ClearFlag(PageFlag::kPageMapped); }
  zx_status_t Unmap();
  zx_status_t Map();

  // Each Setxxx() method atomically sets a flag and returns the previous value.
  // It should be called when the first reference is made in FileCache::GetPageUnsafe().
  bool SetActive() { return SetFlag(PageFlag::kPageActive); }
  // It should be called after the last reference is destroyed in FileCache::Downgrade().
  void ClearActive() { ClearFlag(PageFlag::kPageActive); }

  void Lock() {
    while (flags_[static_cast<uint8_t>(PageFlag::kPageLocked)].test_and_set(
        std::memory_order_acquire)) {
      flags_[static_cast<uint8_t>(PageFlag::kPageLocked)].wait(true, std::memory_order_relaxed);
    }
  }
  bool TryLock() {
    if (!flags_[static_cast<uint8_t>(PageFlag::kPageLocked)].test_and_set(
            std::memory_order_acquire)) {
      return false;
    }
    return true;
  }
  void Unlock() {
    if (IsLocked()) {
      ClearFlag(PageFlag::kPageLocked);
      WakeupFlag(PageFlag::kPageLocked);
    }
  }

  // A caller MUST NOT acquire FileCache::tree_lock_ before calling it.
  void WaitOnWriteback();
  bool SetWriteback();
  void ClearWriteback();

  bool SetUptodate();
  void ClearUptodate();

  bool SetDirty();
  bool ClearDirtyForIo(bool for_writeback);

  void SetMmapped();
  // It clears PageFlag::kPageMmapped. If the Page is mmapped, it returns true.
  // If the Page is modified like Invalidate(), it should be synchronized to mmaped area.
  bool ClearMmapped();

  // Truncate and punch-a-hole operations call it to invalidate a Page.
  // It clears PageFlag::kPageUptodate. If the Page is dirty, it clears PageFlag::kPageDirty and
  // decreases corresponding dirty page count.
  // Note that it does not wait for a writeback Page to be written out. So, a caller ensure that its
  // block address is invalidated in a dnode or nat entry before calling it.
  void Invalidate();

  void ZeroUserSegment(uint64_t start, uint64_t end) {
    if (start < end && end <= BlockSize()) {
      std::memset(GetAddress<uint8_t>() + start, 0, end - start);
    }
  }

  uint32_t BlockSize() const { return kPageSize; }

  zx_status_t VmoWrite(const void *buffer, uint64_t offset, size_t buffer_size);
  zx_status_t VmoRead(void *buffer, uint64_t offset, size_t buffer_size);

 protected:
  // It requests ZX_VMO_OP_UNLOCK to allow the kernel to reclaim the committed page after
  // releasing mappings. If |this| still remains in FileCache, it downgrades the strong reference
  // to a weak pointer. Otherwise, delete |this|.
  void RecyclePage();

 private:
  void WaitOnFlag(PageFlag flag) {
    while (flags_[static_cast<uint8_t>(flag)].test(std::memory_order_acquire)) {
      flags_[static_cast<uint8_t>(flag)].wait(true, std::memory_order_relaxed);
    }
  }
  bool TestFlag(PageFlag flag) const {
    return flags_[static_cast<uint8_t>(flag)].test(std::memory_order_acquire);
  }
  void ClearFlag(PageFlag flag) {
    flags_[static_cast<uint8_t>(flag)].clear(std::memory_order_relaxed);
  }
  void WakeupFlag(PageFlag flag) { flags_[static_cast<uint8_t>(flag)].notify_all(); }
  bool SetFlag(PageFlag flag) {
    return flags_[static_cast<uint8_t>(flag)].test_and_set(std::memory_order_acquire);
  }

  // A virtual address mapped to |vmo_|. It is valid only when IsMapped() returns true.
  // It is unmapped when there is no reference to a clean page
  zx_vaddr_t address_ = 0;
  // It is used to track the status of a page by using PageFlag
  std::array<std::atomic_flag, static_cast<uint8_t>(PageFlag::kPageFlagSize)> flags_ = {
      ATOMIC_FLAG_INIT};
  // It contains the data of the block at |index_|.
  // TODO: when resizeable paged_vmo is available, clone a part of paged_vmo
#ifdef __Fuchsia__
  zx::vmo vmo_;
#else
  FsBlock blk_;
#endif
  // It indicates FileCache to which |this| belongs.
  // It is only use for Downgrade() or unit tests.
  FileCache *file_cache_ = nullptr;
  // It is used as the key of |this| in a lookup table (i.e., FileCache::page_tree_).
  // It indicates different information according to the type of FileCache::vnode_ such as file,
  // node, and meta vnodes. For file vnodes, it has file offset. For node vnodes, it indicates the
  // node id. For meta vnode, it points to the block address to which the metadata is written.
  pgoff_t index_ = -1;

 protected:
  F2fs *fs_ = nullptr;
};

class FileCache {
 public:
  FileCache(VnodeF2fs *vnode);
  FileCache() = delete;
  FileCache(const FileCache &) = delete;
  FileCache &operator=(const FileCache &) = delete;
  FileCache(const FileCache &&) = delete;
  FileCache &operator=(const FileCache &&) = delete;
  ~FileCache();

  // It returns a locked Page with |index| from the lookup |page_tree_|.
  // If there is no corresponding Page in |page_tree_|, it returns a locked Page after creating
  // and inserting it into |page_tree_|.
  // Do release a Page lock before calling methods acquiring |page_lock_|.
  zx_status_t GetPage(const pgoff_t index, fbl::RefPtr<Page> *out) __TA_EXCLUDES(tree_lock_);
  // It does the same things as GetPage() except that it returns a unlocked Page.
  zx_status_t FindPage(const pgoff_t index, fbl::RefPtr<Page> *out) __TA_EXCLUDES(tree_lock_);
  // It tries to write out dirty Pages that |operation| indicates from |page_tree_|.
  pgoff_t Writeback(WritebackOperation &operation) __TA_EXCLUDES(tree_lock_);
  // It removes and invalidates Pages within the range of |start| to |end| in |page_tree_|.
  void InvalidatePages(pgoff_t start, pgoff_t end) __TA_EXCLUDES(tree_lock_);
  // It removes all Pages from |page_tree_|. It should be called when no one can get access to
  // |vnode_|. (e.g., fbl_recycle()) It assumes that all active Pages are under writeback.
  void Reset() __TA_EXCLUDES(tree_lock_);
  VnodeF2fs &GetVnode() const { return *vnode_; }
  // It is only allowed to call it from Page::fbl_recycle.
  void Downgrade(Page *raw_page) __TA_EXCLUDES(tree_lock_);

 private:
  // It returns a set of dirty Pages that meet |operation|. A caller should unlock the Pages.
  std::vector<fbl::RefPtr<Page>> GetLockedDirtyPagesUnsafe(const WritebackOperation &operation)
      __TA_REQUIRES(tree_lock_);
  zx::status<bool> GetPageUnsafe(const pgoff_t index, fbl::RefPtr<Page> *out)
      __TA_REQUIRES(tree_lock_);
  zx_status_t AddPageUnsafe(const fbl::RefPtr<Page> &page) __TA_REQUIRES(tree_lock_);
  zx_status_t EvictUnsafe(Page *page) __TA_REQUIRES(tree_lock_);
  // It evicts all Pages within the range of |start| to |end|. For inactive Pages, it evicts and
  // deletes them since no one refers to them. If |invalidate| is set to true, they are invalidated
  // first. For active Pages, it just evicts and returns them since waiting for writeback of active
  // Pages with tree_lock_ held can cause deadlock due to the contention between
  // CleanupPagesUnsafe() and Downgrade(). When a caller resets returned Pages after doing some
  // necessary work, they will be released.
  std::vector<fbl::RefPtr<Page>> CleanupPagesUnsafe(pgoff_t start = 0, pgoff_t end = kPgOffMax,
                                                    bool invalidate = false)
      __TA_REQUIRES(tree_lock_);

  using PageTreeTraits = fbl::DefaultKeyedObjectTraits<pgoff_t, Page>;
  using PageTree = fbl::WAVLTree<pgoff_t, Page *, PageTreeTraits>;

  fs::SharedMutex tree_lock_;
  std::condition_variable_any recycle_cvar_;
  PageTree page_tree_ __TA_GUARDED(tree_lock_);
  VnodeF2fs *vnode_ = nullptr;
};

}  // namespace f2fs

#endif  // SRC_STORAGE_F2FS_FILE_CACHE_H_
