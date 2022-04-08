// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fidl/test.types/cpp/natural_types.h>

#include <gtest/gtest.h>

namespace {

zx::event MakeEvent() {
  zx::event event;
  zx_status_t status = zx::event::create(0, &event);
  ZX_ASSERT(status == ZX_OK);
  return event;
}

TEST(StrictUnion, Construction) {
  // Strict union is not default constructible.
  static_assert(!std::is_default_constructible_v<test_types::TestUnion>);
  static_assert(!std::is_default_constructible_v<test_types::TestStrictXUnion>);

  // As are any aggregates thereof.
  static_assert(!std::is_default_constructible_v<test_types::TestStrictXUnionInStruct>,
                "Struct of strict union is not default constructible");
  static_assert(!std::is_default_constructible_v<test_types::TestStrictXUnionInArrayInStruct>,
                "Strict union is not default constructible");

  test_types::TestUnion value = test_types::TestUnion::WithCopyable({{.x = 42}});
  EXPECT_TRUE(value.copyable());
  EXPECT_TRUE(value.copyable().has_value());
  EXPECT_EQ(value.copyable().value().x(), 42);
  EXPECT_EQ(value.copyable()->x(), 42);
}

TEST(StrictUnion, Move) {
  // Moving a value union recursively moves fields instead of clearing the union.
  test_types::TestStrictXUnion value = test_types::TestStrictXUnion::WithCopyable({{.x = 42}});
  test_types::TestStrictXUnion value2 = std::move(value);
  EXPECT_EQ(value.Which(), test_types::TestStrictXUnion::Tag::kCopyable);
  EXPECT_EQ(value.copyable().value().x(), 42);
  EXPECT_EQ(value2.Which(), test_types::TestStrictXUnion::Tag::kCopyable);
  EXPECT_EQ(value2.copyable().value().x(), 42);

  // They do not share the same storage.
  value.copyable().value().x() = 0;
  EXPECT_EQ(value2.copyable().value().x(), 42);

  // Moving a resource union recursively moves fields instead of clearing the union.
  test_types::TestUnion resource = test_types::TestUnion::WithMoveOnly({{.h = MakeEvent()}});
  test_types::TestUnion resource2 = std::move(resource);
  EXPECT_EQ(resource.Which(), test_types::TestUnion::Tag::kMoveOnly);
  EXPECT_TRUE(resource.move_only().has_value());
  EXPECT_FALSE(resource.move_only()->h().is_valid());
  EXPECT_EQ(resource2.Which(), test_types::TestUnion::Tag::kMoveOnly);
  EXPECT_TRUE(resource2.move_only().has_value());
  EXPECT_TRUE(resource2.move_only()->h().is_valid());

  // They do not share the same storage.
  resource.move_only()->h() = MakeEvent();
  EXPECT_NE(resource2.move_only()->h(), resource.move_only()->h());
}

TEST(FlexibleUnion, Construction) {
  test_types::TestXUnion default_unknown;
  EXPECT_EQ(default_unknown.Which(), test_types::TestXUnion::Tag::kUnknown);
  EXPECT_FALSE(default_unknown.primitive().has_value());
  EXPECT_FALSE(default_unknown.copyable().has_value());
  EXPECT_FALSE(default_unknown.h().has_value());

  test_types::TestXUnion value = test_types::TestXUnion::WithCopyable({{.x = 42}});
  EXPECT_TRUE(value.copyable());
  EXPECT_TRUE(value.copyable().has_value());
  EXPECT_EQ(value.copyable().value().x(), 42);
  EXPECT_EQ(value.copyable()->x(), 42);
}

// In flexible unions it might be tempting to reset the moved-from union to an
// unknown state. Here, we explicitly choose to only recursively move fields to
// align with strict unions.
TEST(FlexibleUnion, Move) {
  // Moving a value union recursively moves fields instead of clearing the union.
  test_types::TestNonResourceXUnion value = test_types::TestNonResourceXUnion::WithPrimitive(42);
  test_types::TestNonResourceXUnion value2 = std::move(value);
  EXPECT_EQ(value.Which(), test_types::TestNonResourceXUnion::Tag::kPrimitive);
  EXPECT_EQ(value.primitive().value(), 42);
  EXPECT_EQ(value2.Which(), test_types::TestNonResourceXUnion::Tag::kPrimitive);
  EXPECT_EQ(value2.primitive().value(), 42);

  // They do not share the same storage.
  value.primitive().value() = 0;
  EXPECT_EQ(value2.primitive().value(), 42);

  // Moving a resource union recursively moves fields instead of clearing the union.
  test_types::TestXUnion resource = test_types::TestXUnion::WithH(MakeEvent());
  test_types::TestXUnion resource2 = std::move(resource);
  EXPECT_EQ(resource.Which(), test_types::TestXUnion::Tag::kH);
  EXPECT_TRUE(resource.h().has_value());
  EXPECT_FALSE(resource.h()->is_valid());
  EXPECT_EQ(resource2.Which(), test_types::TestXUnion::Tag::kH);
  EXPECT_TRUE(resource2.h().has_value());
  EXPECT_TRUE(resource2.h()->is_valid());

  // They do not share the same storage.
  resource.h().value() = MakeEvent();
  EXPECT_NE(resource2.h().value(), resource.h().value());
}

// These operations should be common across strict/flexible unions.
TEST(Union, SetAndGetFields) {
  test_types::TestXUnion u;
  u.primitive() = 42;
  EXPECT_EQ(u.Which(), test_types::TestXUnion::Tag::kPrimitive);
  u.copyable() = test_types::CopyableStruct{42};
  EXPECT_EQ(u.Which(), test_types::TestXUnion::Tag::kCopyable);
  u.h() = MakeEvent();
  EXPECT_EQ(u.Which(), test_types::TestXUnion::Tag::kH);
  EXPECT_EQ(u.primitive().value_or(0), 0);
}

TEST(Union, IntoOptional) {
  test_types::TestXUnion u;
  u.primitive() = 42;
  std::optional<int32_t> p = u.primitive();
  EXPECT_TRUE(p.has_value());
  EXPECT_EQ(p.value(), 42);

  test_types::TestXUnion mu;
  u.h() = MakeEvent();
  std::optional<zx::handle> h = u.h().take();
  EXPECT_TRUE(h.has_value());
  EXPECT_TRUE(h.value().is_valid());
}

TEST(Union, Copy) {
  static_assert(!std::is_copy_constructible_v<test_types::TestXUnion>,
                "Resource type is not copyable");
  static_assert(!std::is_copy_assignable_v<test_types::TestXUnion>,
                "Resource type is not copyable");
  static_assert(std::is_copy_constructible_v<test_types::TestNonResourceXUnion>,
                "Value type is copyable");
  static_assert(std::is_copy_assignable_v<test_types::TestNonResourceXUnion>,
                "Value type is copyable");

  test_types::TestNonResourceXUnion value = test_types::TestNonResourceXUnion::WithPrimitive(42);
  test_types::TestNonResourceXUnion value2 = value;
  EXPECT_EQ(value.Which(), test_types::TestNonResourceXUnion::Tag::kPrimitive);
  EXPECT_EQ(value.primitive().value(), 42);
  EXPECT_EQ(value2.Which(), test_types::TestNonResourceXUnion::Tag::kPrimitive);
  EXPECT_EQ(value2.primitive().value(), 42);

  // They do not share the same storage.
  value.primitive().value() = 0;
  EXPECT_EQ(value2.primitive().value(), 42);
}

TEST(Union, Equality) {
  test_types::TestStrictXUnion u = test_types::TestStrictXUnion::WithPrimitive(42);
  test_types::TestStrictXUnion different1 = test_types::TestStrictXUnion::WithPrimitive(0);
  test_types::TestStrictXUnion different2 = test_types::TestStrictXUnion::WithCopyable({{.x = 0}});

  EXPECT_EQ(u, u);
  EXPECT_EQ(u, test_types::TestStrictXUnion{u});
  EXPECT_NE(u, different1);
  EXPECT_NE(u, different2);
}

}  // namespace
