// Copyright 2018 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package codegen

const fileTestBaseTmpl = `
{{- define "Filename:TestBase" -}}
fidl/{{ .LibraryDots }}/cpp/wire_test_base.h
{{- end }}


{{- define "File:TestBase" -}}
{{- UseWire -}}
// WARNING: This file is machine generated by fidlgen.

#pragma once

#include <{{ .Library | Filename "Header" }}>

{{- range .Decls }}
  {{- if Eq .Kind Kinds.Protocol }}{{ $protocol := .}}
  {{- range $transport, $_ := .Transports }}{{- if eq $transport "Channel" }}
{{ EnsureNamespace $protocol.TestBase }}


class {{ $protocol.TestBase.Name }} : public {{ $protocol.WireServer }} {
  public:
  virtual ~{{ $protocol.TestBase.Name }}() { }
  virtual void NotImplemented_(const std::string& name, ::fidl::CompleterBase& completer) = 0;

  {{- range $protocol.Methods }}
    {{- if .HasRequest }}
    virtual void {{ .Name }}(
        {{ .WireRequestViewArg }} request, {{ .WireCompleterArg }}& _completer) override {
          NotImplemented_("{{ .Name }}", _completer); }
    {{- end }}
  {{- end }}
};
  {{- end }}
{{- end }}{{ end }}{{ end -}}

{{ EndOfFile }}
{{ end }}
`
