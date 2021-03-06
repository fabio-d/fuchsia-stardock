// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <lib/stdcompat/bit.h>
#include <string.h>

#include <algorithm>

#include <fbl/alloc_checker.h>
#include <region-alloc/region-alloc.h>

// Support for Pool allocated bookkeeping
RegionAllocator::RegionPool::RefPtr RegionAllocator::RegionPool::Create(size_t max_memory) {
  // Sanity check our allocation arguments.
  if (SLAB_SIZE > max_memory) {
    return nullptr;
  }

  fbl::AllocChecker ac;
  auto ret = fbl::AdoptRef(new (&ac) RegionPool(max_memory / SLAB_SIZE));

  if (!ac.check()) {
    return nullptr;
  }

  return ret;
}

RegionAllocator::~RegionAllocator() {
  // No one should be destroying us while we have allocations in flight.
  ZX_DEBUG_ASSERT(allocated_regions_by_base_.is_empty());

  // We should have the same number of regions sorted by base address and by
  // size.
  ZX_DEBUG_ASSERT(avail_regions_by_base_.size() == avail_regions_by_size_.size());

  // Return all of our bookkeeping to our region pool.
  avail_regions_by_base_.clear();
  while (!avail_regions_by_size_.is_empty()) {
    DestroyRegion(avail_regions_by_size_.pop_front());
  }
}

void RegionAllocator::Reset() {
  fbl::AutoLock alloc_lock(&alloc_lock_);

  Region* removed;
  while ((removed = avail_regions_by_base_.pop_front()) != nullptr) {
    avail_regions_by_size_.erase(*removed);
    DestroyRegion(removed);
  }

  ZX_DEBUG_ASSERT(avail_regions_by_base_.is_empty());
  ZX_DEBUG_ASSERT(avail_regions_by_size_.is_empty());
}

zx_status_t RegionAllocator::SetRegionPool(const RegionPool::RefPtr& region_pool) {
  fbl::AutoLock alloc_lock(&alloc_lock_);

  if (!allocated_regions_by_base_.is_empty() || !avail_regions_by_base_.is_empty()) {
    return ZX_ERR_BAD_STATE;
  }

  region_pool_ = region_pool;
  return ZX_OK;
}

zx_status_t RegionAllocator::AddRegion(const ralloc_region_t& region, AllowOverlap allow_overlap) {
  fbl::AutoLock alloc_lock(&alloc_lock_);

  // Start with sanity checks
  zx_status_t ret = AddSubtractSanityCheckLocked(region);
  if (ret != ZX_OK) {
    return ret;
  }

  // Make sure that we do not intersect with the available regions if we do
  // not allow overlaps.
  if ((allow_overlap != AllowOverlap::Yes) && IntersectsLocked(avail_regions_by_base_, region)) {
    return ZX_ERR_INVALID_ARGS;
  }

  // All sanity checks passed.  Grab a piece of free bookkeeping from our pool,
  // fill it out, then add it to the sets of available regions (indexed by
  // base address as well as size)
  Region* to_add = CreateRegion();
  if (to_add == nullptr) {
    return ZX_ERR_NO_MEMORY;
  }

  to_add->base = region.base;
  to_add->size = region.size;

  AddRegionToAvailLocked(to_add, allow_overlap);

  return ZX_OK;
}

zx_status_t RegionAllocator::SubtractRegion(const ralloc_region_t& to_subtract,
                                            AllowIncomplete allow_incomplete) {
  fbl::AutoLock alloc_lock(&alloc_lock_);

  // Start with sanity checks
  zx_status_t ret = AddSubtractSanityCheckLocked(to_subtract);
  if (ret != ZX_OK) {
    return ret;
  }

  // Make a copy of the region to subtract.  We may need to modify the region
  // as part of the subtraction algorithm.
  ralloc_region_t region = to_subtract;

  // Find the region whose base address is <= the specified region (if any).
  // If we do not allow incomplete subtraction, this is the region which must
  // entirely contain the subtracted region.
  //
  // Additionally, the only time we should ever need any extra bookkeeping
  // allocation is if this region (if present) needs to be split into two
  // regions.
  auto before = avail_regions_by_base_.upper_bound(region.base);
  auto after = before--;
  uint64_t region_end = region.base + region.size;  // exclusive end
  uint64_t before_end = 0;

  if (before.IsValid()) {
    before_end = before->base + before->size;  // exclusive end
    if ((region.base >= before->base) && (region_end <= before_end)) {
      // Looks like we found an available region which completely contains the
      // region to be subtracted.  Handle the 4 possible cases.

      // Case 1: The regions are the same.  This one is easy.
      if ((region.base == before->base) && (region_end == before_end)) {
        Region* removed = avail_regions_by_base_.erase(before);
        avail_regions_by_size_.erase(*removed);
        DestroyRegion(removed);
        return ZX_OK;
      }

      // Case 2: before completely contains region.  The before region needs
      // to be split into two regions.  If we are out of bookkeeping space, we
      // are out of luck.
      if ((region.base != before->base) && (region_end != before_end)) {
        Region* second = CreateRegion();
        if (second == nullptr) {
          return ZX_ERR_NO_MEMORY;
        }

        // Looks like we have the memory we need.  Compute the base/size of
        // the two regions which will be left over, then update the first
        // region's position in the size index, and add the second region to
        // the set of available regions.
        Region* first = avail_regions_by_size_.erase(*before);
        first->size = region.base - first->base;
        second->base = region_end;
        second->size = before_end - region_end;

        avail_regions_by_size_.insert(first);
        avail_regions_by_base_.insert(second);
        avail_regions_by_size_.insert(second);
        return ZX_OK;
      }

      // Case 3: region trims the front of before.  Update before's base and
      // size, and recompute its position in the size index.  Note: there is
      // no need to recompute its position in the base index, this has not
      // changed.
      if (region.base == before->base) {
        ZX_DEBUG_ASSERT(region_end < before_end);

        Region* bptr = avail_regions_by_size_.erase(*before);
        bptr->base += region.size;
        bptr->size -= region.size;
        avail_regions_by_size_.insert(bptr);

        return ZX_OK;
      }

      // Case 4: region trims the end of before.  Update before's size and
      // recompute its position in the size index.
      ZX_DEBUG_ASSERT(region.base != before->base);
      ZX_DEBUG_ASSERT(region_end == before_end);

      Region* bptr = avail_regions_by_size_.erase(*before);
      bptr->size -= region.size;
      avail_regions_by_size_.insert(bptr);

      return ZX_OK;
    }
  }

  // If we have gotten this far, then there is no single region in the
  // available set which completely contains the subtraction region.  We
  // cannot continue unless allow_incomplete is Yes.
  if (allow_incomplete != AllowIncomplete::Yes) {
    return ZX_ERR_INVALID_ARGS;
  }

  // Great!  At this point we know that we are going to succeed, we just need
  // to go about updating all of the bookkeeping.  We may need to trim the end
  // of the region which comes before us, and then consume some of the regions
  // which come after us, finishing by trimming the front of (at most) one of
  // the regions which comes after us.  At no point in time do we need to
  // allocate any more bookkeeping, success is guaranteed.  Start by
  // considering the before region.
  if (before.IsValid()) {
    ZX_DEBUG_ASSERT(region.base >= before->base);
    ZX_DEBUG_ASSERT(region_end > before_end);
    if (before_end > region.base) {
      // No matter what, 'before' needs to be removed from the size index.
      Region* bptr = avail_regions_by_size_.erase(*before);

      // If before's base is the same as the region's base, then we are
      // subtracting out all of before.  Otherwise, we are trimming the back
      // before and need to recompute its size and position in the size index.
      if (bptr->base == region.base) {
        avail_regions_by_base_.erase(*bptr);
        DestroyRegion(bptr);
      } else {
        bptr->size = region.base - bptr->base;
        avail_regions_by_size_.insert(bptr);
      }

      // Either way, the region we are subtracting now starts where before
      // used to end.
      region.base = before_end;
      region.size = region_end - region.base;
      ZX_DEBUG_ASSERT(region.size > 0);
    }
  }

  // While there are regions whose base address comes after the base address
  // of what we want to subtract, we need to do one of three things...
  //
  // 1) Consume entire regions which are contained entirely within our
  //    subtraction region.
  // 2) Trim the front of a region which is clipped by our subtraction region.
  // 3) Stop because all remaining regions start after the end of our
  //    subtraction region.
  while (after.IsValid()) {
    ZX_DEBUG_ASSERT(after->base > region.base);

    // Case #3
    if (after->base >= region_end) {
      break;
    }

    // Cases #1 and #2.  No matter what, we need to...
    // 1) Advance after, re-naming the old 'after' to 'trim in the process.
    // 2) Remove trim from the size index.
    auto trim_iter = after++;
    Region* trim = avail_regions_by_size_.erase(*trim_iter);
    uint64_t trim_end = trim->base + trim->size;

    if (trim_end > region_end) {
      // Case #2.  We are guaranteed to be done at this point.
      trim->base = region_end;
      trim->size = trim_end - trim->base;
      avail_regions_by_size_.insert(trim);
      break;
    }

    // Case #1.  Advance the subtraction region to the end of the region we
    // just trimmed into oblivion.  If we have run out of region to trim,
    // then we know we are done.
    avail_regions_by_base_.erase(*trim);
    region.base = trim_end;
    region.size = region_end - region.base;
    DestroyRegion(trim);

    if (!region.size) {
      break;
    }
  }

  // Sanity check.  The number of elements in the base index should match the
  // number of elements in the size index.
  ZX_DEBUG_ASSERT(avail_regions_by_base_.size() == avail_regions_by_size_.size());
  return ZX_OK;
}

zx_status_t RegionAllocator::GetRegion(uint64_t size, uint64_t alignment,
                                       Region::UPtr& out_region) {
  fbl::AutoLock alloc_lock(&alloc_lock_);

  // Sanity check the arguments.
  out_region = nullptr;
  if (!size || !alignment || !cpp20::has_single_bit(alignment)) {
    return ZX_ERR_INVALID_ARGS;
  }

  // Compute the things we will need round-up align base addresses.
  uint64_t mask = alignment - 1;
  uint64_t inv_mask = ~mask;

  // Start by using our size index to look up the first available region which
  // is large enough to hold this allocation (if any)
  auto iter = avail_regions_by_size_.lower_bound({.base = 0, .size = size});

  // Consider all of the regions which are large enough to hold our
  // allocation.  Stop as soon as we find one which can satisfy the alignment
  // restrictions.
  uint64_t aligned_base = 0;
  while (iter.IsValid()) {
    ZX_DEBUG_ASSERT(iter->size >= size);
    aligned_base = (iter->base + mask) & inv_mask;
    uint64_t overhead = aligned_base - iter->base;
    uint64_t leftover = iter->size - size;

    // We have a usable region if the aligned base address has not wrapped
    // the address space, and if overhead required to align the allocation
    // is not larger than what is leftover in the region after performing
    // the allocation.
    if ((aligned_base >= iter->base) && (overhead <= leftover)) {
      break;
    }

    ++iter;
  }

  if (!iter.IsValid()) {
    return ZX_ERR_NOT_FOUND;
  }

  return AllocFromAvailLocked(iter, out_region, aligned_base, size);
}

zx_status_t RegionAllocator::GetRegion(const ralloc_region_t& requested_region,
                                       Region::UPtr& out_region) {
  fbl::AutoLock alloc_lock(&alloc_lock_);

  uint64_t base = requested_region.base;
  uint64_t size = requested_region.size;

  // Sanity check the arguments.
  out_region = nullptr;
  if (!size || ((base + size) < base)) {
    return ZX_ERR_INVALID_ARGS;
  }

  // Find the first available region whose base address is strictly greater
  // than the one we are looking for, then back up one.
  auto iter = avail_regions_by_base_.upper_bound(base);
  --iter;

  // If the iterator is invalid, then we cannot satisfy this request.  If it
  // is valid, then we can satisfy this request if and only if the region we
  // found completely contains the requested region.
  if (!iter.IsValid()) {
    return ZX_ERR_NOT_FOUND;
  }

  // We know that base must be >= iter->base
  // We know that iter->size is non-zero.
  // Therefore, we know that base is in the range [iter.start, iter.end]
  // We know that request.end is > base
  // Therefore request.end is > iter.base
  //
  // So, if request.end <= iter.end, we know that request is completely
  // contained within iter.  It does not matter if we use the inclusive or
  // exclusive end to check, as long as we are consistent.
  ZX_DEBUG_ASSERT(iter->size > 0);
  ZX_DEBUG_ASSERT(iter->base <= base);
  uint64_t req_end = base + size - 1;
  uint64_t iter_end = iter->base + iter->size - 1;
  if (req_end > iter_end) {
    return ZX_ERR_NOT_FOUND;
  }

  // Great, we have found a region which should be able to satisfy our
  // allocation request.  Get an iterator for the by-size index, then use the
  // common AllocFromAvailLocked method to handle the bookkeeping involved.
  auto by_size_iter = avail_regions_by_size_.make_iterator(*iter);
  return AllocFromAvailLocked(by_size_iter, out_region, base, size);
}

zx_status_t RegionAllocator::AddSubtractSanityCheckLocked(const ralloc_region_t& region) {
  // Sanity check the region to make sure that it is well formed.  We do not
  // allow a region which is of size zero, or which wraps around the
  // allocation space.
  if ((region.base + region.size) <= region.base) {
    return ZX_ERR_INVALID_ARGS;
  }

  // Next, make sure the region we are adding or subtracting does not
  // intersect any region which is currently allocated.
  if (IntersectsLocked(allocated_regions_by_base_, region)) {
    return ZX_ERR_INVALID_ARGS;
  }

  return ZX_OK;
}

void RegionAllocator::ReleaseRegion(Region* region) {
  fbl::AutoLock alloc_lock(&alloc_lock_);

  ZX_DEBUG_ASSERT(region != nullptr);

  // When a region comes back from a user, it should be in the
  // allocated_regions_by_base tree, but not in either of the avail_regions
  // trees, and not in any free list.  Remove it from the allocated_regions
  // bookkeeping and add it back to the available regions.
  ZX_DEBUG_ASSERT(fbl::InContainer<SortByBaseTag>(*region));
  ZX_DEBUG_ASSERT(!fbl::InContainer<SortBySizeTag>(*region));

  allocated_regions_by_base_.erase(*region);
  AddRegionToAvailLocked(region);
}

zx_status_t RegionAllocator::AllocFromAvailLocked(Region::WAVLTreeSortBySize::iterator source,
                                                  Region::UPtr& out_region, uint64_t base,
                                                  uint64_t size) {
  ZX_DEBUG_ASSERT(out_region == nullptr);
  ZX_DEBUG_ASSERT(source.IsValid());
  ZX_DEBUG_ASSERT(base >= source->base);
  ZX_DEBUG_ASSERT(size <= source->size);

  uint64_t overhead = base - source->base;
  ZX_DEBUG_ASSERT(overhead < source->size);

  uint64_t leftover = source->size - size;
  ZX_DEBUG_ASSERT(leftover >= overhead);

  // Great, we found a region.  We may have to split the available region into
  // up to 2 sub regions depending on where the aligned allocation lies in the
  // region.  Figure out how much splitting we need to do and attempt to
  // allocate the bookkeeping.
  bool split_before = base != source->base;
  bool split_after = overhead < leftover;

  if (!split_before && !split_after) {
    // If no splits are required, then this should be easy.  Take the region
    // out of the avail bookkeeping, add it to the allocated bookkeeping and
    // we are finished.
    Region* region = avail_regions_by_size_.erase(source);
    avail_regions_by_base_.erase(*region);
    allocated_regions_by_base_.insert(region);
    out_region.reset(region);
  } else if (!split_before) {
    // If we only have to split after, then this region is aligned with what
    // we want to allocate, but we will not use all of it.  Break it into
    // two pieces and return the one which comes first.
    Region* before_region = CreateRegion();
    if (before_region == nullptr) {
      return ZX_ERR_NO_MEMORY;
    }

    Region* after_region = avail_regions_by_size_.erase(source);

    before_region->base = after_region->base;
    before_region->size = size;
    after_region->base += size;
    after_region->size -= size;

    avail_regions_by_size_.insert(after_region);
    allocated_regions_by_base_.insert(before_region);

    out_region.reset(before_region);
  } else if (!split_after) {
    // If we only have to split before, then this region is not aligned
    // properly with what we want to allocate, but we will use the entire
    // region (after aligning).  Break it into two pieces and return the one
    // which comes after.
    Region* after_region = CreateRegion();
    if (after_region == nullptr) {
      return ZX_ERR_NO_MEMORY;
    }

    Region* before_region = avail_regions_by_size_.erase(source);

    after_region->base = base;
    after_region->size = size;
    before_region->size -= size;

    avail_regions_by_size_.insert(before_region);
    allocated_regions_by_base_.insert(after_region);

    out_region.reset(after_region);
  } else {
    // Looks like we need to break our region into 3 chunks and return the
    // middle chunk.  Start by grabbing the bookkeeping we require first.
    Region* region = CreateRegion();
    if (region == nullptr) {
      return ZX_ERR_NO_MEMORY;
    }

    Region* after_region = CreateRegion();
    if (after_region == nullptr) {
      DestroyRegion(region);
      return ZX_ERR_NO_MEMORY;
    }

    Region* before_region = avail_regions_by_size_.erase(source);

    region->base = before_region->base + overhead;
    region->size = size;
    after_region->base = region->base + region->size;
    after_region->size = before_region->size - size - overhead;
    before_region->size = overhead;

    avail_regions_by_size_.insert(before_region);
    avail_regions_by_size_.insert(after_region);
    avail_regions_by_base_.insert(after_region);
    allocated_regions_by_base_.insert(region);

    out_region.reset(region);
  }
  return ZX_OK;
}

void RegionAllocator::AddRegionToAvailLocked(Region* region, AllowOverlap allow_overlap) {
  // Sanity checks.  This region should not exist in any bookkeeping, and
  // should not overlap with any of the regions we are currently tracking.
  ZX_DEBUG_ASSERT(!fbl::InContainer<SortByBaseTag>(*region));
  ZX_DEBUG_ASSERT(!fbl::InContainer<SortBySizeTag>(*region));
  ZX_DEBUG_ASSERT(!IntersectsLocked(allocated_regions_by_base_, *region));
  ZX_DEBUG_ASSERT((allow_overlap == AllowOverlap::Yes) ||
                  !IntersectsLocked(avail_regions_by_base_, *region));

  // Find the region which comes before us and the region which comes after us
  // in the tree.
  auto before = avail_regions_by_base_.upper_bound(region->base);
  auto after = before--;

  // Merge with the region which comes before us if we can.
  uint64_t region_end = (region->base + region->size);  // exclusive end
  if (before.IsValid()) {
    ZX_DEBUG_ASSERT(before->base <= region->base);

    uint64_t before_end = (before->base + before->size);  // exclusive end
    if ((allow_overlap == AllowOverlap::Yes) ? (before_end >= region->base)
                                             : (before_end == region->base)) {
      region_end = std::max(region_end, before_end);
      region->base = before->base;

      auto removed = avail_regions_by_base_.erase(before);
      avail_regions_by_size_.erase(*removed);
      DestroyRegion(removed);
    }
  }

  // Merge with the region which comes after us if we can, keep merging if we
  // allow overlaps.
  while (after.IsValid()) {
    ZX_DEBUG_ASSERT(region->base < after->base);

    if (!((allow_overlap == AllowOverlap::Yes) ? (region_end >= after->base)
                                               : (region_end == after->base))) {
      break;
    }

    uint64_t after_end = (after->base + after->size);
    region_end = std::max(region_end, after_end);

    auto remove_me = after++;
    auto removed = avail_regions_by_base_.erase(remove_me);
    avail_regions_by_size_.erase(*removed);
    DestroyRegion(removed);

    if (allow_overlap != AllowOverlap::Yes) {
      break;
    }
  }

  // Update the region's size to reflect any mergers which may have taken
  // place, then add the region to the two indexes.
  region->size = region_end - region->base;
  avail_regions_by_base_.insert(region);
  avail_regions_by_size_.insert(region);
}

bool RegionAllocator::IntersectsLocked(const Region::WAVLTreeSortByBase& tree,
                                       const ralloc_region_t& region) const {
  // Find the first entry in the tree whose base is >= region.base.  If this
  // element exists, and its base is < the exclusive end of region, then
  // we have an intersection.
  auto iter = tree.lower_bound(region.base);
  if (iter.IsValid() && (iter->base < (region.base + region.size))) {
    return true;
  }

  // Check the element before us in the tree.  If it exists, we know that it's
  // base is < region.base.  If it's exclusive end is >= region.base, then we
  // have an intersection.
  --iter;
  if (iter.IsValid() && (region.base < (iter->base + iter->size))) {
    return true;
  }

  return false;
}

bool RegionAllocator::ContainedByLocked(const Region::WAVLTreeSortByBase& tree,
                                        const ralloc_region_t& region) const {
  // Find the first entry in the tree whose base is > region.base, then back up
  // one.  Our iterator now points to the first entry in a set of disjoint
  // regions sorted by ascending base address, whose base address is <= to ours.
  //
  // If we are completely contained by any block, it must be this one.  We
  // already know that the region after this one (if any) has a base address which is
  // strictly > than |region|, so it cannot contain |region|.  Also,
  // All of the regions are disjoint (by nature of the data structure).  So, any
  // region which comes before |iter| one must have an end address strictly < the
  // base address of |iter|.  Since |region|'s base address is >= |iter|'s base
  // address, we know that the region which comes before |iter| cannot contain
  // region either.
  auto iter = --(tree.upper_bound(region.base));
  if (iter.IsValid() && ((iter->base + iter->size) >= (region.base + region.size))) {
    return true;
  }

  return false;
}

RegionAllocator::Region* RegionAllocator::CreateRegion() {
  if (region_pool_ != nullptr) {
    return region_pool_->New(this);
  } else {
    fbl::AllocChecker ac;
    Region* ret = new (&ac) Region(this);
    return ac.check() ? ret : nullptr;
  }
}

void RegionAllocator::DestroyRegion(Region* region) {
  ZX_DEBUG_ASSERT(region != nullptr);
  if (region_pool_ != nullptr) {
    region_pool_->Delete(region);
  } else {
    delete region;
  }
}
