// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fuchsia/hardware/power/statecontrol/cpp/fidl.h>
#include <fuchsia/modular/internal/cpp/fidl.h>
#include <lib/async-loop/cpp/loop.h>
#include <lib/async-loop/default.h>
#include <lib/fit/defer.h>
#include <lib/fit/function.h>
#include <lib/sys/cpp/component_context.h>
#include <lib/sys/inspect/cpp/component.h>
#include <lib/syslog/cpp/log_settings.h>
#include <lib/syslog/cpp/macros.h>
#include <lib/trace-provider/provider.h>
#include <zircon/assert.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <string>

#include "fuchsia/session/cpp/fidl.h"
#include "lib/stdcompat/string_view.h"
#include "src/lib/files/directory.h"
#include "src/lib/files/path.h"
#include "src/lib/fxl/command_line.h"
#include "src/lib/fxl/strings/string_number_conversions.h"
#include "src/modular/bin/basemgr/basemgr_impl.h"
#include "src/modular/bin/basemgr/child_listener.h"
#include "src/modular/bin/basemgr/cobalt/cobalt.h"
#include "src/modular/bin/basemgr/inspector.h"
#include "src/modular/lib/modular_config/modular_config.h"
#include "src/modular/lib/modular_config/modular_config_accessor.h"
#include "src/modular/lib/modular_config/modular_config_constants.h"

// Command-line command to delete the persistent configuration.
constexpr std::string_view kDeletePersistentConfigCommand = "delete_persistent_config";

// Command-line flag that specifies the name of a v2 child that basemgr will
// start and monitor for crashes.
constexpr std::string_view kEagerChildFlag = "eager-child";

// Command-line flag that specifies the name of a v2 child that basemgr will
// start and monitor for crashes. Unlike `eager-child`, child components specified
// with this flag will yield a session restart if the component can not be
// started.
constexpr std::string_view kCriticalChildFlag = "critical-child";

// Command-line flag that specifies the base used for calculating exponential
// backoff delay. Value should be a positive integer, in minutes. Default value
// is 2.
constexpr std::string_view kBackoffBaseFlag = "backoff-base-minutes";

// Base number used for calculating exponential backoff delay. The idea here
// is that the delay, in minutes, would equal kBackoffBase ^ attempt. This
// is used exclusively for child components marked as "eager".
constexpr std::string_view kBackoffBase = "2";

fit::deferred_action<fit::closure> SetupCobalt(bool enable_cobalt, async_dispatcher_t* dispatcher,
                                               sys::ComponentContext* component_context) {
  if (!enable_cobalt) {
    return fit::defer<fit::closure>([] {});
  }
  return modular::InitializeCobalt(dispatcher, component_context);
}

class LifecycleHandler : public fuchsia::process::lifecycle::Lifecycle {
 public:
  explicit LifecycleHandler(modular::BasemgrImpl* basemgr_impl, async::Loop* loop)
      : basemgr_impl_(basemgr_impl), loop_(loop) {
    FX_DCHECK(basemgr_impl_);
    FX_DCHECK(loop_);

    zx::channel lifecycle_request{zx_take_startup_handle(PA_LIFECYCLE)};
    if (lifecycle_request) {
      bindings_.AddBinding(this,
                           fidl::InterfaceRequest<fuchsia::process::lifecycle::Lifecycle>(
                               std::move(lifecycle_request)),
                           loop_->dispatcher());
    } else {
      FX_LOGS(WARNING) << "Lifecycle startup handle is not valid. "
                          "basemgr will not shut down cleanly.";
    }
  }

  // |fuchsia.process.lifecycle.Lifecycle|
  void Stop() override {
    basemgr_impl_->Stop();
    loop_->Quit();
    bindings_.CloseAll();
  }

 private:
  modular::BasemgrImpl* const basemgr_impl_;  // Not owned.
  async::Loop* const loop_;                   // Not owned.

  fidl::BindingSet<fuchsia::process::lifecycle::Lifecycle> bindings_;
};

std::unique_ptr<modular::BasemgrImpl> CreateBasemgrImpl(
    modular::ModularConfigAccessor config_accessor, std::vector<modular::Child> children,
    size_t backoff_base, sys::ComponentContext* component_context,
    modular::BasemgrInspector* inspector, async::Loop* loop) {
  fit::deferred_action<fit::closure> cobalt_cleanup = SetupCobalt(
      config_accessor.basemgr_config().enable_cobalt(), loop->dispatcher(), component_context);

  auto child_listener = std::make_unique<modular::ChildListener>(
      component_context->svc().get(), loop->dispatcher(), std::move(children), backoff_base);

  return std::make_unique<modular::BasemgrImpl>(
      std::move(config_accessor), component_context->outgoing(), inspector,
      component_context->svc()->Connect<fuchsia::sys::Launcher>(),
      component_context->svc()->Connect<fuchsia::ui::policy::Presenter>(),
      component_context->svc()->Connect<fuchsia::hardware::power::statecontrol::Admin>(),
      component_context->svc()->Connect<fuchsia::session::Restarter>(), std::move(child_listener),
      /*on_shutdown=*/
      [loop, cobalt_cleanup = std::move(cobalt_cleanup), component_context]() mutable {
        cobalt_cleanup.call();
        component_context->outgoing()->debug_dir()->RemoveEntry(modular_config::kBasemgrConfigName);
        loop->Quit();
      });
}

std::string GetUsage() {
  return R"(Usage: basemgr [<command>]

  <command>
    (none)                    Launches basemgr.
    delete_persistent_config  Deletes any existing persistent configuration, and exits.

# Flags

  --eager-child

    Child component which basemgr will launch and monitor for crashes. basemgr
    will start the child component by connecting to the FIDL Protocol `fuchsia.component.Binder`
    hosted under the path `fuchsia.component.Binder.<child>`. Therefore, it is expected
    that a corresponding `use from child` clause is present in basemgr's manifest
    and that the child component exposes `fuchsia.component.Binder`.
    Normally, the use clause will be structured like so:

    ```
    use: [
      {
        protocol: "fuchsia.component.Binder",
        from: "#foo", // Where `foo` is the child name
        path: "/svc/fuchsia.component.Binder.foo",
      },
      ...
    ]
    ```

    basemgr will attempt to start the child 3 total times. After the 3rd attempt,
    basemgr will move on and no future attempts will be made.

    Note: This field is mutually exclusive with --critical-child. A child can't
    be marked as both eager and critical.

  --critical-child

    Similar setup as --eager-child, except that these components are critical
    to the session. Unlike with eager children, basemgr will only attempt one
    connection. If basemgr can't establish a connection with a critical
    child or if the child crashes at any point, basemgr will restart the session.

    Note: This field is mutually exclusive with --eager-child. A child can't
    be marked as both eager and critical.

  --backoff-base-minutes

    Specifies the base used for calculating exponential backoff delay. Value
    should be a positive integer, in minutes. Default value is 2.


basemgr cannot be launched from the shell. Please use `basemgr_launcher` or `run`.
)";
}

int main(int argc, const char** argv) {
  syslog::SetTags({"basemgr"});

  auto config_reader = modular::ModularConfigReader::CreateFromNamespace();
  auto config_writer = modular::ModularConfigWriter::CreateFromNamespace();

  // Process command line arguments.
  const auto command_line = fxl::CommandLineFromArgcArgv(argc, argv);

  const auto& positional_args = command_line.positional_args();
  if (positional_args.size() == 1 && positional_args[0] == kDeletePersistentConfigCommand) {
    if (auto result = config_writer.Delete(); result.is_error()) {
      std::cerr << result.take_error() << std::endl;
      return EXIT_FAILURE;
    }
    std::cout << "Deleted persistent configuration." << std::endl;
    return EXIT_SUCCESS;
  }

  if (!positional_args.empty()) {
    std::cerr << GetUsage() << std::endl;
    FX_LOGS(ERROR) << "Exiting because positional_args not empty";
    return EXIT_FAILURE;
  }

  // Read configuration.
  auto config_result = config_reader.ReadAndMaybePersistConfig(&config_writer);
  if (config_result.is_error()) {
    std::cerr << config_result.take_error() << std::endl;
    return EXIT_FAILURE;
  }

  async::Loop loop(&kAsyncLoopConfigAttachToCurrentThread);
  trace::TraceProviderWithFdio trace_provider(loop.dispatcher());
  std::unique_ptr<sys::ComponentContext> component_context(
      sys::ComponentContext::CreateAndServeOutgoingDirectory());

  auto component_inspector = std::make_unique<sys::ComponentInspector>(component_context.get());
  component_inspector->Health().Ok();

  auto inspector = std::make_unique<modular::BasemgrInspector>(component_inspector->inspector());
  inspector->AddConfig(config_reader.GetConfig());

  // Child components to start.
  std::vector<modular::Child> children = {};
  auto critical_children = command_line.GetOptionValues(kCriticalChildFlag);
  std::transform(
      critical_children.cbegin(), critical_children.cend(), std::back_inserter(children),
      [](const std::string_view& name) { return modular::Child{.name = name, .critical = true}; });

  auto eager_children = command_line.GetOptionValues(kEagerChildFlag);
  std::transform(eager_children.cbegin(), eager_children.cend(), std::back_inserter(children),
                 [&critical_children](const std::string_view& name) {
                   bool is_marked_critical =
                       std::find_if(critical_children.begin(), critical_children.end(),
                                    [=](std::string_view other) { return other == name; }) !=
                       critical_children.end();
                   if (is_marked_critical) {
                     FX_LOGS(ERROR) << "Exiting because child name " << name.data()
                                    << " marked as both --critical-child and --eager-child";
                     exit(EXIT_FAILURE);
                   }

                   return modular::Child{.name = name, .critical = false};
                 });

  auto backoff_base_str = command_line.GetOptionValueWithDefault(kBackoffBaseFlag, kBackoffBase);
  size_t backoff_base = 0;
  if (!fxl::StringToNumberWithError(backoff_base_str, &backoff_base)) {
    FX_LOGS(ERROR) << "Exiting because " << kBackoffBaseFlag
                   << " was set to non-numeric value: " << kBackoffBase;
    return EXIT_FAILURE;
  }

  auto basemgr_impl =
      CreateBasemgrImpl(modular::ModularConfigAccessor(config_result.take_value()), children,
                        backoff_base, component_context.get(), inspector.get(), &loop);

  LifecycleHandler lifecycle_handler{basemgr_impl.get(), &loop};

  basemgr_impl->Start();

  // NOTE: component_controller.events.OnDirectoryReady() is triggered when a
  // component's out directory has mounted. basemgr_launcher uses this signal
  // to determine when basemgr has completed initialization so it can detach
  // and stop itself. When basemgr_launcher is used, it's responsible for
  // providing basemgr a configuration file. To ensure we don't shutdown
  // basemgr_launcher too early, we need additions to out/ to complete after
  // configurations have been parsed.
  component_context->outgoing()->debug_dir()->AddEntry(
      modular_config::kBasemgrConfigName,
      std::make_unique<vfs::Service>([basemgr_impl = basemgr_impl.get()](
                                         zx::channel request, async_dispatcher_t* /* unused */) {
        basemgr_impl->Connect(
            fidl::InterfaceRequest<fuchsia::modular::internal::BasemgrDebug>(std::move(request)));
      }));

  loop.Run();

  // The loop will run until graceful shutdown is complete so returning SUCCESS here indicates that.
  return EXIT_SUCCESS;
}
