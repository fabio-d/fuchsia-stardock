// Copyright 2022 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The parseoutput package defines types and functions for serializing/deserializing
// network-conformance test output for consumption by infra tooling (e.g. testparser).
package parseoutput

import (
	"encoding/json"
	"fmt"
	"regexp"
)

var (
	TestPreamblePattern = regexp.MustCompile(
		`\[network-conformance case start\]`,
	)
	CaseEndPattern = regexp.MustCompile(
		`\[network-conformance case end\] (.*)$`,
	)
)

const NetworkConformanceFormatName = "NetworkConformanceTest"

type CaseIdentifier struct {
	Platform    string `json:"platform"`
	SuiteName   string `json:"suite_name"`
	MajorNumber int    `json:"major_number"`
	MinorNumber int    `json:"minor_number"`
}

func (i CaseIdentifier) String() string {
	return fmt.Sprintf(
		"%s--%s-%d.%d",
		i.Platform,
		i.SuiteName,
		i.MajorNumber,
		i.MinorNumber,
	)
}

type CaseStart struct {
	Identifier CaseIdentifier `json:"identifier"`
}

type CaseEnd struct {
	Identifier      CaseIdentifier `json:"identifier"`
	ExpectedOutcome string         `json:"expected_outcome"`
	ActualOutcome   string         `json:"actual_outcome"`
	DurationMillis  int64          `json:"duration_millis"`
}

// Given a line from test output, if that line represents the end of a
// network-conformance test case, returns the data for that test case, whether
// or not a case was found in that line, and any error encountered while parsing
// the case data.
func ParseNetworkConformanceCaseEnd(line string) (CaseEnd, bool, error) {
	m := CaseEndPattern.FindStringSubmatch(line)
	if m == nil {
		return CaseEnd{}, false, nil
	}

	caseEndData := m[1]
	var parsedCaseEnd CaseEnd
	if err := json.Unmarshal([]byte(caseEndData), &parsedCaseEnd); err != nil {
		return CaseEnd{}, true, fmt.Errorf(
			"error while parsing \"%s\" for network conformance case end: %w",
			line,
			err,
		)
	}
	return parsedCaseEnd, true, nil
}
