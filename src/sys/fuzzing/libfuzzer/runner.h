// Copyright 2021 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SRC_SYS_FUZZING_LIBFUZZER_RUNNER_H_
#define SRC_SYS_FUZZING_LIBFUZZER_RUNNER_H_

#include <fuchsia/fuzzer/cpp/fidl.h>
#include <lib/fdio/spawn.h>
#include <lib/fit/function.h>
#include <lib/zx/process.h>

#include <memory>
#include <string_view>

#include <re2/re2.h>

#include "src/sys/fuzzing/common/async-types.h"
#include "src/sys/fuzzing/common/input.h"
#include "src/sys/fuzzing/common/runner.h"
#include "src/sys/fuzzing/libfuzzer/process.h"

namespace fuzzing {

using ::fuchsia::fuzzer::Status;

// The concrete implementation of |Runner| for the libfuzzer engine.
class LibFuzzerRunner : public Runner {
 public:
  ~LibFuzzerRunner() override = default;

  // Factory method.
  static RunnerPtr MakePtr(ExecutorPtr executor);

  void set_cmdline(const std::vector<std::string>& cmdline) { cmdline_ = cmdline; }
  void set_verbose(bool verbose) { verbose_ = verbose; }

  // |Runner| methods.
  void AddDefaults(Options* options) override;
  zx_status_t AddToCorpus(CorpusType corpus_type, Input input) override;
  Input ReadFromCorpus(CorpusType corpus_type, size_t offset) override;
  zx_status_t ParseDictionary(const Input& input) override;
  Input GetDictionaryAsInput() const override;

  ZxPromise<> Configure(const OptionsPtr& options) override;
  ZxPromise<FuzzResult> Execute(Input input) override;
  ZxPromise<Input> Minimize(Input input) override;
  ZxPromise<Input> Cleanse(Input input) override;
  ZxPromise<Artifact> Fuzz() override;
  ZxPromise<> Merge() override;

  ZxPromise<> Stop() override;

  Status CollectStatus() override;

 protected:
  // Creates the list of actions to perform when spawning libFuzzer. Returns pipes to |stdin| and
  // from |stderr|.
  std::vector<fdio_spawn_action_t> MakeSpawnActions(int* stdin_fd, int* stderr_fd);

 private:
  explicit LibFuzzerRunner(ExecutorPtr executor);

  // Construct a set of libFuzzer command-line arguments for the current options.
  std::vector<std::string> MakeArgs();

  // Returns a promise that runs a libFuzzer process asynchronously and returns the fuzzing result
  // and the input that caused it.
  ZxPromise<Artifact> RunAsync(std::vector<std::string> args);

  // Returns a promise that reads the output of the process run by |RunAsync|. The promise will
  // update the fuzzer status accordingly, and return the fuzzing result when idenitifed.
  ZxPromise<FuzzResult> ParseOutput();

  // Attempts to interpret the line as containing information from libFuzzer.
  // Returns the fuzzing result or error detected in libFuzzer's output, or |fpromise:ok(NO_ERRORS)|
  // if neither is found.
  ZxResult<FuzzResult> ParseLine(const std::string& line);

  // Attempts to interpret the line as containing status information from libFuzzer.
  // Returns true if |line| is status, false otherwise.
  void ParseStatus(re2::StringPiece* input);

  // Attempts to interpret the line as containing error information from libFuzzer.
  ZxResult<FuzzResult> ParseError(re2::StringPiece* input);

  // Update the list of input files in the live corpus.
  void ReloadLiveCorpus();

  std::vector<std::string> cmdline_;
  OptionsPtr options_;

  // Immutable set of inputs. These will be kept on merge.
  std::vector<std::string> seed_corpus_;

  // Dynamic set of inputs. Inputs may be added during fuzzing, and/or may be removed when merging.
  std::vector<std::string> live_corpus_;

  bool has_dictionary_ = false;
  zx::time start_;

  // If true, eachoes the piped stderr to this process's stderr.
  bool verbose_ = true;

  Status status_;
  std::string result_input_pathname_;
  bool minimized_ = false;

  // Asynchronous process used to run libFuzzer instances.
  Process process_;
  Barrier barrier_;
  Workflow workflow_;

  FXL_DISALLOW_COPY_ASSIGN_AND_MOVE(LibFuzzerRunner);
};

}  // namespace fuzzing

#endif  // SRC_SYS_FUZZING_LIBFUZZER_RUNNER_H_
