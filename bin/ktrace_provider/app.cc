// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "apps/tracing/src/ktrace_provider/app.h"

#include <fcntl.h>
#include <unistd.h>

#include <magenta/device/ktrace.h>
#include <magenta/syscalls/log.h>
#include <trace-engine/instrumentation.h>
#include <trace-provider/provider.h>

#include "apps/tracing/src/ktrace_provider/importer.h"
#include "apps/tracing/src/ktrace_provider/reader.h"
#include "lib/ftl/arraysize.h"
#include "lib/ftl/files/file.h"
#include "lib/ftl/logging.h"
#include "lib/mtl/tasks/message_loop.h"

namespace ktrace_provider {
namespace {

constexpr char kKTraceDev[] = "/dev/misc/ktrace";

struct KTraceCategory {
  const char* name;
  uint32_t group;
};

constexpr KTraceCategory kGroupCategories[] = {
    {"kernel", KTRACE_GRP_ALL},
    {"kernel:meta", KTRACE_GRP_META},
    {"kernel:lifecycle", KTRACE_GRP_LIFECYCLE},
    {"kernel:sched", KTRACE_GRP_SCHEDULER},
    {"kernel:tasks", KTRACE_GRP_TASKS},
    {"kernel:ipc", KTRACE_GRP_IPC},
    {"kernel:irq", KTRACE_GRP_IRQ},
    {"kernel:probe", KTRACE_GRP_PROBE},
    {"kernel:arch", KTRACE_GRP_ARCH},
};

constexpr char kLogCategory[] = "log";

ftl::UniqueFD OpenKTrace() {
  int result = open(kKTraceDev, O_WRONLY);
  if (result < 0) {
    FTL_LOG(ERROR) << "Failed to open " << kKTraceDev << ": errno=" << errno;
  }
  return ftl::UniqueFD(result);  // take ownership here
}

void IoctlKtraceStop(int fd) {
  mx_status_t status = ioctl_ktrace_stop(fd);
  if (status != MX_OK)
    FTL_LOG(ERROR) << "ioctl_ktrace_stop failed: status=" << status;
}

void IoctlKtraceStart(int fd, uint32_t group_mask) {
  mx_status_t status = ioctl_ktrace_start(fd, &group_mask);
  if (status != MX_OK)
    FTL_LOG(ERROR) << "ioctl_ktrace_start failed: status=" << status;
}

}  // namespace

App::App(const ftl::CommandLine& command_line)
    : application_context_(app::ApplicationContext::CreateFromStartupInfo()) {
  trace_observer_.Start(mtl::MessageLoop::GetCurrent()->async(),
                        [this] { UpdateState(); });
}

App::~App() {}

void App::UpdateState() {
  uint32_t group_mask = 0;
  bool capture_log = false;
  if (trace_state() == TRACE_STARTED) {
    for (size_t i = 0; i < arraysize(kGroupCategories); i++) {
      auto& category = kGroupCategories[i];
      if (trace_is_category_enabled(category.name)) {
        group_mask |= category.group;
      }
    }
    capture_log = trace_is_category_enabled(kLogCategory);
  }

  if (current_group_mask_ != group_mask) {
    StopKTrace();
    StartKTrace(group_mask);
  }

  if (capture_log) {
    log_importer_.Start();
  } else {
    log_importer_.Stop();
  }
}

void App::StartKTrace(uint32_t group_mask) {
  FTL_DCHECK(!context_);
  if (!group_mask) {
    return;  // nothing to trace
  }

  FTL_LOG(INFO) << "Starting ktrace";

  ftl::UniqueFD fd = OpenKTrace();
  if (!fd.is_valid()) {
    return;
  }

  context_ = trace_acquire_context();
  if (!context_) {
    // Tracing was disabled in the meantime.
    return;
  }
  current_group_mask_ = group_mask;

  IoctlKtraceStop(fd.get());
  IoctlKtraceStart(fd.get(), group_mask);

  FTL_LOG(INFO) << "Started ktrace";
}

void App::StopKTrace() {
  if (!context_) {
    return;  // not currently tracing
  }
  FTL_DCHECK(current_group_mask_);

  FTL_LOG(INFO) << "Stopping ktrace";

  ftl::UniqueFD fd = OpenKTrace();
  if (fd.is_valid()) {
    IoctlKtraceStop(fd.get());
  }

  Reader reader;
  Importer importer(context_);
  if (!importer.Import(reader)) {
    FTL_LOG(ERROR) << "Errors encountered while importing ktrace data";
  }

  trace_release_context(context_);
  context_ = nullptr;
  current_group_mask_ = 0u;
}

}  // namespace ktrace_provider
