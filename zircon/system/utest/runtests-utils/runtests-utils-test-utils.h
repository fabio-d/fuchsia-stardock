// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ZIRCON_SYSTEM_UTEST_RUNTESTS_UTILS_RUNTESTS_UTILS_TEST_UTILS_H_
#define ZIRCON_SYSTEM_UTEST_RUNTESTS_UTILS_RUNTESTS_UTILS_TEST_UTILS_H_

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string_view>

#include <fbl/string.h>
#include <fbl/string_buffer.h>
#include <fbl/unique_fd.h>
#include <fbl/vector.h>
#include <runtests-utils/runtests-utils.h>
#include <zxtest/zxtest.h>

namespace runtests {

static constexpr char kExpectedJSONOutputPrefix[] = "{\n  \"tests\": [\n";
// We don't want to count the null terminator.
static constexpr size_t kExpectedJSONOutputPrefixSize = sizeof(kExpectedJSONOutputPrefix) - 1;

fbl::String packaged_script_dir();

// Represents a script generated at build time, selected from the appropriate
// target directory.
class PackagedScriptFile {
 public:
  explicit PackagedScriptFile(std::string_view path);
  ~PackagedScriptFile();
  std::string_view path() const;

 private:
  fbl::String path_;
};

// Creates an empty file and deletes it in its destructor.
class ScopedStubFile {
 public:
  explicit ScopedStubFile(std::string_view path);
  ~ScopedStubFile();

 private:
  const std::string_view path_;
};

// Creates a script file with given contents in its constructor and deletes it
// in its destructor.
class ScopedTestFile {
 public:
  // |path| is the path of the file to be created.
  //
  // |contents| are the script contents. Shebang line will be added automatically.
  ScopedTestFile(std::string_view path, std::string_view file);
  ~ScopedTestFile();
  std::string_view path() const;

 private:
  const std::string_view path_;
};

// Creates a subdirectory of |parent| in its constructor and deletes it in
// its destructor.
class ScopedTestDir {
 public:
  explicit ScopedTestDir(const char* parent)
      : basename_(NextBasename()), path_(JoinPath(parent, basename_)) {
    if (mkdir(path_.c_str(), 0755)) {
      printf("FAILURE: mkdir failed to open %s: %s\n", path_.c_str(), strerror(errno));
      exit(1);
    }
  }
  ~ScopedTestDir() { CleanUpDir(path_.c_str()); }
  const char* basename() { return basename_.c_str(); }
  const char* path() { return path_.c_str(); }

 private:
  static fbl::String NextBasename() {
    // More than big enough to print INT_MAX.
    char buf[64];
    sprintf(buf, "%d", num_test_dirs_created_++);
    return fbl::String(buf);
  }

  // Recursively removes the directory at |dir_path| and its contents.
  static void CleanUpDir(const char* dir_path) {
    DIR* dp = opendir(dir_path);
    if (dp == nullptr) {
      printf("FAILURE: opendir failed to open %s: %s\n", dir_path, strerror(errno));
      exit(1);
    }

    struct dirent* entry;
    while ((entry = readdir(dp))) {
      // Skip "." and "..".
      if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
        continue;
      }
      fbl::String entry_path = JoinPath(dir_path, entry->d_name);
      if (entry->d_type == DT_DIR) {
        CleanUpDir(entry_path.c_str());
      } else {
        remove(entry_path.c_str());
      }
    }
    closedir(dp);

    // Directory is now empty: remove it.
    rmdir(dir_path);
  }

  const fbl::String basename_;
  const fbl::String path_;

  // Used to generate unique subdirectories of |parent|.
  static int num_test_dirs_created_;
};

class TestStopwatch : public Stopwatch {
 public:
  void Start() override { start_called_ = true; }
  int64_t DurationInMsecs() override {
    EXPECT_TRUE(start_called_);
    return 14u;
  }

 private:
  bool start_called_ = false;
};

// Returns the number of files or subdirectories in a given directory.
int NumEntriesInDir(const char* dir_path);

// Computes the relative path within |output_dir| of the output file of the
// test at |test_path|, setting |output_file_rel_path| as its value if
// successful.
// Returns true iff successful.
bool GetOutputFileRelPath(std::string_view output_dir, std::string_view test_path,
                          fbl::String* output_file_rel_path);

}  // namespace runtests

#endif  // ZIRCON_SYSTEM_UTEST_RUNTESTS_UTILS_RUNTESTS_UTILS_TEST_UTILS_H_
