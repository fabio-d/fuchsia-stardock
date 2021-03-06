// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <lib/media/codec_impl/codec_diagnostics.h>
#include <lib/media/codec_impl/log.h>

std::atomic<trace_counter_id_t> CodecDiagnostics::CurrentTraceCounter = 0;

CodecDiagnostics::CodecDiagnostics(DriverDiagnostics& driver_diagnostics, inspect::Node root)
    : driver_diagnostics_(driver_diagnostics),
      root_(std::move(root)),
      utilizing_hardware_(root_.CreateUint(kCurrentlyUtilizingHardware, 0)),
      allocation_(root_.CreateDouble(kAllocation, 0.0)),
      total_allocated_time_(root_.CreateUint(kTotalAllocatedTime, 0)) {}

CodecDiagnostics::~CodecDiagnostics() {
  // Inform the driver diagnostics that the codec implementation is being destroyed
  if (currently_utilizing_hardware_) {
    driver_diagnostics_.get().DecrementCurrentlyDecoding();
  }

  driver_diagnostics_.get().RemoveCodec();
}

// Update the hardware utilization status. This function should be called whenever a variable that
// could effect value of VideoDecoder::IsUtilizingHardware() changes even if the value of
// VideoDecoder::IsUtilizingHardware() has not changed from the previous call to this function. The
// reason is so that this function can take into account the passage of time and update durations
// stored by this class accordingly. This will also effect the allocation which is calculated and
// published by this function.
void CodecDiagnostics::UpdateHardwareUtilizationStatus(zx::time now, bool is_utilizing_hardware) {
  // Get the total time from the last time we checked
  zx::duration total_time = now - last_checked_time_;

  // If we are allocated then add the time our allocation
  if (is_utilizing_hardware) {
    total_allocated_time_.Add(total_time.to_nsecs());
  }

  zx::duration active_time = is_utilizing_hardware ? total_time : zx::nsec(0);

  bool coalesced = false;
  if (!time_periods_.empty()) {
    auto& last_time_period = time_periods_.back();
    auto start_time = time_periods_.back().end_time - time_periods_.back().total_time;
    if (now - start_time < kBucketDuration) {
      coalesced = true;
      last_time_period.end_time = now;
      last_time_period.total_time += total_time;
      last_time_period.active_time += active_time;
    }
  }

  if (!coalesced) {
    time_periods_.emplace_back(now, total_time, active_time);
  }

  while (!time_periods_.empty() && (now - time_periods_.front().end_time > kMemoryDuration)) {
    time_periods_.pop_front();
  }

  zx::duration total_time_accumulate(0);
  zx::duration active_time_accumulate(0);
  for (const auto& current_period : time_periods_) {
    active_time_accumulate += current_period.active_time;
    total_time_accumulate += current_period.total_time;
  }

  double utilization = 0.0;
  if (total_time_accumulate != zx::nsec(0)) {
    utilization = 100.0 * (static_cast<double>(active_time_accumulate.to_nsecs()) /
                           static_cast<double>(total_time_accumulate.to_nsecs()));
  }

  allocation_.Set(utilization);
  utilizing_hardware_.Set(is_utilizing_hardware);

  if (TRACE_ENABLED()) {
    PostToSharedDiagnostics([this, utilization] {
      TRACE_COUNTER("media", "Decoder Utilization", trace_counter_id_, "utilization", utilization);
    });
  }

  // See if there was a change in value of currently_utilizing_hardware_ and if so
  // let the DriverDiagnostics class know that our hardware status has changed.
  if (!currently_utilizing_hardware_ && is_utilizing_hardware) {
    driver_diagnostics_.get().IncrementCurrentlyDecoding();
  } else if (currently_utilizing_hardware_ && !is_utilizing_hardware) {
    driver_diagnostics_.get().DecrementCurrentlyDecoding();
  }

  last_checked_time_ = now;
  currently_utilizing_hardware_ = is_utilizing_hardware;
}

void CodecDiagnostics::PostToSharedDiagnostics(fit::closure operation) {
  driver_diagnostics_.get().PostToSharedDiagnostics(std::move(operation));
}

DriverDiagnostics::DriverDiagnostics(std::string_view driver_name)
    : root_(inspector_.GetRoot().CreateChild(driver_name)),
      bind_time_(root_.CreateUint(kBindTime, 0)),
      num_of_active_codecs_(root_.CreateUint(kNumOfActiveCodecs, 0)),
      currently_decoding_(root_.CreateBool(kCurrentlyDecoding, false)) {
  shared_diagnostics_loop_.StartThread("shared_diagnostics_loop_", &shared_diagnostics_thread_);
}

DriverDiagnostics::~DriverDiagnostics() {
  shared_diagnostics_loop_.Quit();
  shared_diagnostics_loop_.JoinThreads();
  shared_diagnostics_loop_.Shutdown();
}

zx::vmo DriverDiagnostics::DuplicateVmo() const { return inspector_.DuplicateVmo(); }

void DriverDiagnostics::SetBindTime() {
  zx_time_t current_time = zx_clock_get_monotonic();
  bind_time_.Set(static_cast<int64_t>(current_time));
}

void DriverDiagnostics::IncrementCurrentlyDecoding() {
  num_of_currently_decoding_ += 1;
  currently_decoding_.Set(true);
}

void DriverDiagnostics::DecrementCurrentlyDecoding() {
  if (num_of_currently_decoding_ > 0) {
    num_of_currently_decoding_ -= 1;
  }

  currently_decoding_.Set(num_of_currently_decoding_ != 0);
}

CodecDiagnostics DriverDiagnostics::CreateCodec(std::string_view codec_name) {
  const std::string& codec_prefix = std::string(codec_name) + "-";
  inspect::Node new_decoder_node = root_.CreateChild(root_.UniqueName(codec_prefix));

  num_of_active_codecs_.Add(1);

  return CodecDiagnostics(*this, std::move(new_decoder_node));
}

void DriverDiagnostics::RemoveCodec() { num_of_active_codecs_.Subtract(1); }

void DriverDiagnostics::PostToSharedDiagnostics(fit::closure operation) {
  zx_status_t task_result =
      async::PostTask(shared_diagnostics_loop_.dispatcher(), std::move(operation));
  if (task_result != ZX_OK) {
    LOG(ERROR, "Could not post task to shared thread");
  }
}
