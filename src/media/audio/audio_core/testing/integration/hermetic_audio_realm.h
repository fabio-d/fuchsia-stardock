// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_MEDIA_AUDIO_AUDIO_CORE_TESTING_INTEGRATION_HERMETIC_AUDIO_REALM_H_
#define SRC_MEDIA_AUDIO_AUDIO_CORE_TESTING_INTEGRATION_HERMETIC_AUDIO_REALM_H_

#include <fuchsia/virtualaudio/cpp/fidl.h>
#include <lib/async/dispatcher.h>
#include <lib/fidl/cpp/synchronous_interface_ptr.h>
#include <lib/inspect/cpp/hierarchy.h>
#include <lib/sys/component/cpp/testing/realm_builder.h>
#include <zircon/types.h>

#include <functional>
#include <memory>
#include <string>
#include <utility>

#include "src/media/audio/effects/test_effects/test_effects_v2.h"

namespace media::audio::test {

class HermeticAudioRealm {
 public:
  ~HermeticAudioRealm();

  struct LocalDirectory {
    // These fields combine to describe a directory `{root}/{subdir}`, where
    // `{root}` is capability in the test component's manifest and `{subdir}`
    // is a relative subdirectory (does not start with `/`).
    std::string root_cabability_name;
    std::string subdir;
  };

  struct Options {
    // audio_core's /config/data directory can be created in one of three ways:
    // 1. empty
    // 2. as a local directory from the test component's namespace
    // 3. from scratch with mapping from file name -> file contents
    std::variant<std::monostate, LocalDirectory, component_testing::DirectoryContents>
        audio_core_config_data;

    // Should we create a V2 effects FIDL server?
    // Not empty => create a server that is backed by the given set of effects.
    // Empty     => don't create a server (if needed, it must be provided by `customize_realm`)
    std::vector<TestEffectsV2::Effect> test_effects_v2;

    // Allow the test to customize the realm.
    std::function<zx_status_t(component_testing::RealmBuilder& realm_builder)> customize_realm;
  };

  // Should be called with ASSERT_NO_FATAL_FAILURE(Create(..)).
  static void Create(Options options, async_dispatcher* dispatcher,
                     std::unique_ptr<HermeticAudioRealm>& realm_out);

  // Connect to a discoverable service exposed by a child component.
  template <typename Interface>
  zx_status_t Connect(fidl::InterfaceRequest<Interface> request) const {
    return root_.Connect(std::move(request));
  }

  // Specializations for fuchsia.virtualaudio.{Input,Output} which are connected in a different way.
  template <>
  zx_status_t Connect(fidl::InterfaceRequest<fuchsia::virtualaudio::Input> request) const {
    return virtual_audio_forwarder_->SendInput(std::move(request));
  }
  template <>
  zx_status_t Connect(fidl::InterfaceRequest<fuchsia::virtualaudio::Output> request) const {
    return virtual_audio_forwarder_->SendOutput(std::move(request));
  }

  // Component names which can be passed to ReadInspect;
  static inline std::string kAudioCore = "audio_core";
  static inline std::string kMockCobalt = "mock_cobalt";
  static inline std::string kThermalTestControl = "thermal_test_control";

  // Read the exported inspect info for the given component.
  const inspect::Hierarchy ReadInspect(std::string_view component_name);

 private:
  class LocalProcessorCreator;

  struct CtorArgs {
    component_testing::RealmRoot root;
    std::unique_ptr<LocalProcessorCreator> local_processor_creator;
  };
  static CtorArgs BuildRealm(Options options, async_dispatcher* dispatcher);

  explicit HermeticAudioRealm(CtorArgs&& args);

  component_testing::RealmRoot root_;
  fidl::SynchronousInterfacePtr<fuchsia::virtualaudio::Forwarder> virtual_audio_forwarder_;
  std::unique_ptr<LocalProcessorCreator> local_processor_creator_;
};

}  // namespace media::audio::test

#endif  // SRC_MEDIA_AUDIO_AUDIO_CORE_TESTING_INTEGRATION_HERMETIC_AUDIO_REALM_H_
