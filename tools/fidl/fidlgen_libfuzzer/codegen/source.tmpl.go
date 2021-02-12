// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package codegen

const tmplSource = `
{{- define "Source" -}}
// WARNING: This file is machine generated by fidlgen.

#include <{{ .PrimaryHeader }}>

#include <lib/async-loop/cpp/loop.h>
#include <lib/async-loop/default.h>
#include <lib/fidl/cpp/fuzzing/fuzzer.h>
#include <lib/fidl/cpp/interface_ptr.h>
#include <lib/zx/channel.h>
#include <zircon/errors.h>
#include <zircon/syscalls.h>
#include <zircon/types.h>

using namespace ::fuzzing;
using namespace {{ range .Library }}::{{ . }}{{ end }};

{{- $protocols := Protocols .Decls }}

// Add //build/fuzzing:fuzzing_verbose_logging to a GN target's configs to enable.
#if FUZZING_VERBOSE_LOGGING
#include <stdio.h>
#define xprintf(fmt...) printf(fmt)
#else
#define xprintf(fmt...) \
  do {                  \
  } while (0)
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data_, size_t size_) {
  static ::async::Loop* loop_ = nullptr;

  if (loop_ == nullptr) {
    xprintf("Starting client async loop\n");
    loop_ = new ::async::Loop(&kAsyncLoopConfigAttachToCurrentThread);
  }

  // Must fuzz some protocol; first two bytes used to select protocol and method.
  if (size_ < 2) {
    xprintf("Early exit: Input too small: %zu\n", size_);
    return 0;
  }
  size_ -= 2;

  uint8_t protocol_selector_ = data_[0];
  uint8_t protocol_selection_ = protocol_selector_ % {{ len $protocols }};

  xprintf("Starting fuzzer with %zu bytes of data\n", size_);

  // Hardcode mutually-exclusive if blocks that selects exactly one protocol.
  zx_status_t status_;
{{- range $protocolIdx, $protocol := $protocols }}{{ if len $protocol.Methods }}
  if (protocol_selection_ == {{ $protocolIdx }}) {
#if !defined(PROTOCOL_{{ $protocol.FuzzingName }})
    // Selected protocol from FIDL file that is not part of this fuzzer.
    xprintf("Early exit: Chose disabled protocol: {{ $protocol.FuzzingName }}\n");
    return 0;
#else

    ::fidl::InterfacePtr<{{ $protocol.Natural }}> protocol_;

    xprintf("Starting {{ $protocol.FuzzingName }} service\n");
    ::fidl::fuzzing::Fuzzer<{{ $protocol.Natural }}> fuzzer_(loop_->dispatcher());
    if ((status_ = fuzzer_.Init()) != ZX_OK) {
      xprintf("Early exit: fuzzer.Init returned bad status: %d\n", status_);
      return 0;
    }

    if ((status_ = fuzzer_.BindService()) != ZX_OK) {
      xprintf("Early exit: fuzzer.BindService returned bad status: %d\n", status_);
      return 0;
    }

    if ((status_ = fuzzer_.BindClient(&protocol_, loop_->dispatcher())) != ZX_OK) {
      xprintf("Early exit: fuzzer.BindClient returned bad status: %d\n", status_);
      return 0;
    }

    FuzzInput src_(data_, size_);

    uint8_t method_selector_ = data_[1];
    uint8_t method_selection_ = method_selector_ % {{ len $protocol.Methods }};

  {{- range $methodIdx, $method := .Methods }}{{- if len $method.Request }}
    if (method_selection_ == {{ $methodIdx }}) {
#if !(ALL_METHODS || defined(METHOD_{{ $method.Name }}))
      // Selected method from protocol that is not part of this fuzzer.
      xprintf("Early exit: Chose disabled method: {{ $method.Name }}\n");
      return 0;
#else
      const size_t min_size_ = {{ range $paramIdx, $param := $method.Request }}
        {{- if $paramIdx }} + {{ end }}MinSize<{{ $param.Type.Natural }}>()
      {{- end }};

      // Must have enough bytes for input.
      if (size_ < min_size_) {
        xprintf("Early exit: Input size too small: %zu < %zu\n", size_, min_size_);
        return 0;
      }

      const size_t slack_size_ = size_ - min_size_;
      const size_t slack_size_per_param = slack_size_ / {{ len $method.Request }};

      xprintf("Allocating parameters with %zu bytes (%zu bytes each)\n", slack_size_, slack_size_per_param);

      size_t param_size_;
  {{- range $method.Request }}
      param_size_ = MinSize<{{ .Type.Natural }}>() + slack_size_per_param;
      xprintf("Allocating %zu bytes for {{ .Type.Natural }} {{ .Name }}\n", param_size_);
      {{ .Type.Natural }} {{ .Name }} = Allocate<{{ .Type.Natural }}>{}(&src_, &param_size_);
  {{- end }}

      xprintf("Invoking method {{ $protocol.FuzzingName }}.{{ $method.Name }}\n");
      protocol_->{{ $method.Name }}({{ range $paramIdx, $param := $method.Request }}
          {{- if $paramIdx }}, {{ end -}}
          std::move({{ $param.Name }})
        {{- end }}
        {{- if len $method.Response}}
          {{- if len $method.Request }}, {{ end -}}
          [signaller = fuzzer_.NewCallbackSignaller()]({{ range $paramIdx, $param := $method.Response }}
            {{- if $paramIdx }}, {{ end -}}
            {{ $param.Type.Natural }} {{ $param.Name }}
          {{- end }}) {
        xprintf("Invoked {{ $protocol.FuzzingName }}.{{ $method.Name }}\n");
        zx_status_t status_ = signaller.SignalCallback();
        if (status_ != ZX_OK) {
          xprintf("signaller.SignalCallback returned bad status: %d\n", status_);
        }
      }
      {{- end }});
#endif
    }
  {{- end }}{{- end }}

    loop_->RunUntilIdle();

    if ((status_ = fuzzer_.WaitForCallback()) != ZX_OK) {
      xprintf("fuzzer.WaitForCallback returned bad status: %d\n", status_);
    }

    protocol_.Unbind();
#endif
  }
{{- end }}{{ end }}

  xprintf("Fuzzer stopped!\n");

  return 0;
}
{{ end }}
`
