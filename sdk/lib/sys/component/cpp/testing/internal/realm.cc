// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <lib/sys/component/cpp/testing/internal/errors.h>
#include <lib/sys/component/cpp/testing/internal/realm.h>
#include <lib/sys/cpp/component_context.h>
#include <lib/sys/cpp/service_directory.h>

namespace sys {
namespace testing {
namespace internal {

fuchsia::component::RealmSyncPtr CreateRealmPtr(const sys::ComponentContext* context) {
  ZX_SYS_ASSERT_NOT_NULL(context);
  fuchsia::component::RealmSyncPtr realm;
  context->svc()->Connect(realm.NewRequest());
  return realm;
}

ServiceDirectory OpenExposedDir(fuchsia::component::Realm_Sync* realm,
                                const fuchsia::component::decl::ChildRef& child_ref) {
  ZX_SYS_ASSERT_NOT_NULL(realm);
  fuchsia::io::DirectorySyncPtr exposed_dir;
  fuchsia::component::Realm_OpenExposedDir_Result result;
  ZX_SYS_ASSERT_STATUS_AND_RESULT_OK(
      "Realm/OpenExposedDir", realm->OpenExposedDir(child_ref, exposed_dir.NewRequest(), &result),
      result);
  return ServiceDirectory(std::move(exposed_dir));
}

void CreateChild(fuchsia::component::Realm_Sync* realm, std::string collection, std::string name,
                 std::string url) {
  ZX_SYS_ASSERT_NOT_NULL(realm);
  fuchsia::component::decl::CollectionRef collection_ref = {
      .name = collection,
  };
  fuchsia::component::decl::Child child_decl;
  child_decl.set_name(name);
  child_decl.set_url(url);
  child_decl.set_startup(fuchsia::component::decl::StartupMode::LAZY);
  fuchsia::component::Realm_CreateChild_Result result;
  ZX_SYS_ASSERT_STATUS_AND_RESULT_OK(
      "Realm/CreateChild",
      realm->CreateChild(std::move(collection_ref), std::move(child_decl),
                         fuchsia::component::CreateChildArgs{}, &result),
      result);
}

void DestroyChild(fuchsia::component::Realm_Sync* realm,
                  fuchsia::component::decl::ChildRef child_ref) {
  ZX_SYS_ASSERT_NOT_NULL(realm);
  fuchsia::component::Realm_DestroyChild_Result result;
  ZX_SYS_ASSERT_STATUS_AND_RESULT_OK("Realm/DestroyChild",
                                     realm->DestroyChild(std::move(child_ref), &result), result);
}

}  // namespace internal
}  // namespace testing
}  // namespace sys
