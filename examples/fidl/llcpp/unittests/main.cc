// Copyright 2020 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

// [START include]
#include <fidl/fuchsia.examples/cpp/wire.h>
// [END include]

namespace {

using fuchsia_examples::wire::FileMode;

// [START bits]
TEST(FidlExamples, Bits) {
  auto flags = FileMode::kRead | FileMode::kWrite | FileMode::kExecute;
  ASSERT_EQ(flags, FileMode::kMask);
}
// [END bits]

// [START enums]
TEST(FidlExamples, Enums) {
  ASSERT_EQ(static_cast<uint32_t>(fuchsia_examples::wire::LocationType::kMuseum), 1u);
}
// [END enums]

// [START structs]
TEST(FidlExamples, Structs) {
  fuchsia_examples::wire::Color default_color;
  ASSERT_EQ(default_color.id, 0u);
  // Default values are currently not supported.
  ASSERT_TRUE(default_color.name.is_null());
  ASSERT_TRUE(default_color.name.empty());

  fuchsia_examples::wire::Color blue = {1, "blue"};
  ASSERT_EQ(blue.id, 1u);
}
// [END structs]

// [START unions]
TEST(FidlExamples, Unions) {
  fidl::Arena allocator;
  auto int_val = fuchsia_examples::wire::JsonValue::WithIntValue(1);
  ASSERT_TRUE(int_val.is_int_value());
  ASSERT_EQ(1, int_val.int_value());

  auto str_val = fuchsia_examples::wire::JsonValue::WithStringValue(allocator, "1");
  ASSERT_TRUE(str_val.is_string_value());
  ASSERT_EQ("1", str_val.string_value().get());
}
// [END unions]

// [START tables]
TEST(FidlExamples, Tables) {
  fidl::Arena arena;
  // Construct a table creating a builder with an arena.
  auto builder = fuchsia_examples::wire::User::Builder(arena);
  // The |arena| passed to the builder will be used to allocate the table frame,
  // the inline portions of any fields and passed to the constructor of field
  // types.
  builder.name("jdoe");
  // The builder is turned into an actual instance by calling |Build()|.
  auto user = builder.Build();
  ASSERT_FALSE(user.IsEmpty());
  ASSERT_EQ(user.name().get(), "jdoe");
}

TEST(FidlExamples, TablesInlineSetter) {
  fidl::Arena arena;
  // Construct a table creating a builder with an arena.
  auto builder = fuchsia_examples::wire::User::Builder(arena);
  // Small values <= 4 bytes are inlined inside the frame of the table.
  builder.age(30);
  // The builder is turned into an actual instance by calling |Build()|.
  auto user = builder.Build();
  ASSERT_FALSE(user.IsEmpty());
  ASSERT_EQ(user.age(), 30);
}

TEST(FidlExamples, TablesDefaultConstructor) {
  fidl::Arena allocator;
  // In some situations it could be difficult to provide an arena when
  // constructing tables. For example, here it is hard to provide constructor
  // arguments to 10 tables at once. When a table is default constructed, it
  // does not have an associated |fidl::WireTableFrame<T>|. A new table
  // instance should be built and assigned to the default constructed table.
  fidl::Array<fuchsia_examples::wire::User, 10> users;
  for (auto& user : users) {
    ASSERT_TRUE(user.IsEmpty());
    user = fuchsia_examples::wire::User::Builder(allocator).age(30).name("jdoe").Build();
    ASSERT_FALSE(user.IsEmpty());
    ASSERT_EQ(user.age(), 30);
  }
  ASSERT_EQ(users[0].age(), 30);
}
// [END tables]

// [START external-object]
TEST(AllocationExamples, ExternalObject) {
  fidl::StringView str("hello");
  // |object_view| is a view to the string view.
  fidl::ObjectView object_view = fidl::ObjectView<fidl::StringView>::FromExternal(&str);
  fuchsia_examples::wire::JsonValue val =
      fuchsia_examples::wire::JsonValue::WithStringValue(object_view);
  ASSERT_TRUE(val.is_string_value());
}
// [END external-object]

// [START external-vector]
TEST(AllocationExamples, ExternalVector) {
  std::vector<uint32_t> vec = {1, 2, 3, 4};
  fidl::VectorView<uint32_t> vv = fidl::VectorView<uint32_t>::FromExternal(vec);
  ASSERT_EQ(vv.count(), 4UL);
}
// [END external-vector]

// [START external-string]
TEST(AllocationExamples, ExternalString) {
  const char* string = "hello";
  fidl::StringView sv = fidl::StringView::FromExternal(string);
  ASSERT_EQ(sv.size(), 5UL);
}
// [END external-string]

TEST(AllocationExamples, StringViewLiteral) {
  // [START stringview-assign]
  fidl::StringView sv1 = "hello world";
  fidl::StringView sv2("Hello");
  ASSERT_EQ(sv1.size(), 11UL);
  ASSERT_EQ(sv2.size(), 5UL);
  // [END stringview-assign]
}

}  // namespace
