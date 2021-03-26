// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIB_FIDL_LLCPP_STRING_VIEW_H_
#define LIB_FIDL_LLCPP_STRING_VIEW_H_

#include <lib/fidl/llcpp/fidl_allocator.h>
#include <lib/fidl/llcpp/vector_view.h>
#include <lib/fidl/walker.h>
#include <lib/stdcompat/string_view.h>
#include <zircon/fidl.h>

#include <cstring>
#include <string>
#include <type_traits>

namespace fidl {

// A FIDL string that either borrows or owns its contents.
//
// To borrow the contents of an |std::string|,
// use |fidl::unowned_str(my_str)|.
class StringView final : private VectorView<const char> {
 public:
  StringView() : VectorView() {}
  StringView(const char data[], uint64_t size) : VectorView(data, size) {}
  StringView(unowned_ptr_t<const char[]>&& data, uint64_t size)
      : VectorView(std::move(data), size) {}
  explicit StringView(VectorView<char>&& vv) : VectorView(std::move(vv)) {}
  explicit StringView(VectorView<const char>&& vv) : VectorView(std::move(vv)) {}

  // Allocates a string using the allocator.
  StringView(AnyAllocator& allocator, cpp17::string_view from)
      : VectorView(allocator, from.size()) {
    memcpy(const_cast<char*>(VectorView::mutable_data()), from.data(), from.size());
  }

  // Constructs a fidl::StringView referencing a string literal. For example:
  //
  //     fidl::StringView view("hello");
  //     view.size() == 5;
  //
  template <size_t N>
  constexpr StringView(const char (&literal)[N], uint64_t size = N - 1)
      : VectorView(fidl::unowned_ptr_t<const char>(static_cast<const char*>(literal)), size) {
    static_assert(N > 0, "String should not be empty");
  }

  static StringView FromExternal(cpp17::string_view from) { return StringView(from); }
  static StringView FromExternal(const char* data, size_t size) { return StringView(data, size); }

  void Set(AnyAllocator& allocator, cpp17::string_view from) {
    Allocate(allocator, from.size());
    memcpy(const_cast<char*>(VectorView::mutable_data()), from.data(), from.size());
  }

  cpp17::string_view get() const { return {data(), size()}; }

  uint64_t size() const { return count(); }
  void set_size(uint64_t size) { set_count(size); }

  const char* data() const { return VectorView::data(); }

  bool is_null() const { return data() == nullptr; }
  bool empty() const { return size() == 0; }

  const char& at(size_t offset) const { return data()[offset]; }

  const char& operator[](size_t offset) const { return at(offset); }

  const char* begin() const { return data(); }
  const char* cbegin() const { return data(); }

  const char* end() const { return data() + size(); }
  const char* cend() const { return data() + size(); }

 private:
  explicit StringView(cpp17::string_view from) : VectorView(from.data(), from.size()) {}
};

}  // namespace fidl

#endif  // LIB_FIDL_LLCPP_STRING_VIEW_H_
