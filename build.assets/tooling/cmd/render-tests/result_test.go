/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	//go:embed testdata/pass-pass-pass.in
	passPassPass string

	//go:embed testdata/pass-fail-pass.in
	passFailPass string

	//go:embed testdata/pass-fail-skip.in
	passFailSkip string

	//go:embed testdata/flaky-pass.in
	flakyPass string
	//go:embed testdata/flaky-fail-1.in
	flakyFail1 string
	//go:embed testdata/flaky-fail-4.in
	flakyFail4 string
	//go:embed testdata/flaky-fail-5.in
	flakyFail5 string
)

func TestHierarchy(t *testing.T) {
	rr := newRunResult(byPackage, 0)
	feedEvents(t, rr, passFailSkip)

	pkgname := "example.com/package"
	require.Contains(t, rr.packages, pkgname)
	pkg := rr.packages[pkgname]
	require.Contains(t, pkg.tests, pkgname+".TestParse")
	require.Contains(t, pkg.tests, pkgname+".TestEmpty")
	require.Contains(t, pkg.tests, pkgname+".TestParseHostPort")
}

func TestStatus(t *testing.T) {
	rr := newRunResult(byPackage, 0)
	feedEvents(t, rr, passFailSkip)

	require.Equal(t, rr.testCount.pass, 1)
	require.Equal(t, rr.testCount.fail, 1)
	require.Equal(t, rr.testCount.skip, 1)
	require.Equal(t, rr.pkgCount.fail, 1)
	pkgname := "example.com/package"
	pkg := rr.packages[pkgname]
	require.Equal(t, pkg.count.fail, 1)
	require.Equal(t, pkg.tests[pkgname+".TestEmpty"].count.pass, 1)
	require.Equal(t, pkg.tests[pkgname+".TestParse"].count.fail, 1)
	require.Equal(t, pkg.tests[pkgname+".TestParseHostPort"].count.skip, 1)
}

func TestSuccessOutput(t *testing.T) {
	rr := newRunResult(byPackage, 0)
	feedEvents(t, rr, passPassPass)

	pkgname := "example.com/package"
	pkg := rr.packages[pkgname]
	require.Empty(t, pkg.output)
	require.Empty(t, pkg.tests[pkgname+".TestEmpty"].output)
	require.Empty(t, pkg.tests[pkgname+".TestParseHostPort"].output)
	require.Empty(t, pkg.tests[pkgname+".TestParse"].output)
}

func TestFailureOutput(t *testing.T) {
	rr := newRunResult(byPackage, 0)
	feedEvents(t, rr, passFailSkip)

	pkgname := "example.com/package"
	pkg := rr.packages[pkgname]
	require.Empty(t, pkg.tests[pkgname+".TestEmpty"].output)
	require.Empty(t, pkg.tests[pkgname+".TestParseHostPort"].output)
	expectedTestOutput := []string{
		"=== RUN   TestParse\n",
		"=== PAUSE TestParse\n",
		"=== CONT  TestParse\n",
		"    addr_test.go:71: failed\n",
		"--- FAIL: TestParse (0.00s)\n",
	}
	expectedPkgOutput := []string{
		"=== RUN   TestParseHostPort\n",
		"=== PAUSE TestParseHostPort\n",
		"=== RUN   TestEmpty\n",
		"=== PAUSE TestEmpty\n",
		"=== RUN   TestParse\n",
		"=== PAUSE TestParse\n",
		"=== CONT  TestParseHostPort\n",
		"    addr_test.go:32: \n",
		"=== CONT  TestParse\n",
		"--- SKIP: TestParseHostPort (0.00s)\n",
		"=== CONT  TestEmpty\n",
		"    addr_test.go:71: failed\n",
		"--- PASS: TestEmpty (0.00s)\n",
		"--- FAIL: TestParse (0.00s)\n",
		"FAIL\n",
		"\texample.com/package\tcoverage: 2.4% of statements\n",
		"FAIL\texample.com/package\t0.007s\n",
	}
	require.Equal(t, pkg.tests[pkgname+".TestParse"].output, expectedTestOutput)
	require.Equal(t, pkg.output, expectedPkgOutput)
}

func TestPrintTestResultByPackage(t *testing.T) {
	output := &bytes.Buffer{}
	events := strToEvents(t, passFailSkip)
	rr := newRunResult(byPackage, 0)
	for _, event := range events {
		rr.processTestEvent(event)
		rr.printTestResult(output, event)
	}

	expected := "fail   2.4% (in   0.01s): example.com/package\n"
	require.Equal(t, expected, output.String())
}

func TestPrintTestResultByTest(t *testing.T) {
	output := &bytes.Buffer{}
	events := strToEvents(t, passFailSkip)
	rr := newRunResult(byTest, 0)
	for _, event := range events {
		rr.processTestEvent(event)
		rr.printTestResult(output, event)
	}

	expected := `
skip (in   0.00s): example.com/package.TestParseHostPort
pass (in   0.00s): example.com/package.TestEmpty
fail (in   0.00s): example.com/package.TestParse
fail (in   0.01s): example.com/package
`[1:]
	require.Equal(t, expected, output.String())
}

func TestPrintSummaryNoFail(t *testing.T) {
	rr := newRunResult(byTest, 0)
	feedEvents(t, rr, passPassPass)

	output := &bytes.Buffer{}
	rr.printSummary(output)

	expected := `
===================================================
Tests: 3 passed, 0 failed, 0 skipped
Packages: 1 passed, 0 failed, 0 skipped
===================================================
All tests pass. Yay!
`[1:]
	require.Equal(t, expected, output.String())
}

func TestPrintSummaryFail(t *testing.T) {
	rr := newRunResult(byPackage, 0)
	feedEvents(t, rr, passFailPass)

	output := &bytes.Buffer{}
	rr.printSummary(output)

	expected := `
===================================================
Tests: 1 passed, 1 failed, 1 skipped
Packages: 1 passed, 1 failed, 0 skipped
===================================================
FAIL: example.com/package
FAIL: example.com/package.TestParse
===================================================
OUTPUT example.com/package.TestParse
===================================================
=== RUN   TestParse
=== PAUSE TestParse
=== CONT  TestParse
    addr_test.go:71: failed
--- FAIL: TestParse (0.00s)
===================================================
`[1:]
	require.Equal(t, expected, output.String())
}

func TestPrintFlakinessSummaryNoFail(t *testing.T) {
	rr := newRunResult(byFlakiness, 2) // top 2 failures only
	feedEvents(t, rr, flakyPass)
	feedEvents(t, rr, flakyPass)
	feedEvents(t, rr, flakyPass)
	feedEvents(t, rr, flakyPass)

	output := &bytes.Buffer{}
	rr.printFlakinessSummary(output)

	expected := `
===================================================
No flaky tests!
`[1:]
	require.Equal(t, expected, output.String())
}

func TestPrintFlakinessSummaryFail(t *testing.T) {
	rr := newRunResult(byFlakiness, 2) // top 2 failures only
	feedEvents(t, rr, flakyPass)
	feedEvents(t, rr, flakyFail1)
	feedEvents(t, rr, flakyPass)
	feedEvents(t, rr, flakyFail4)
	feedEvents(t, rr, flakyFail5)
	feedEvents(t, rr, flakyFail5)
	feedEvents(t, rr, flakyFail5)
	feedEvents(t, rr, flakyPass)
	feedEvents(t, rr, flakyFail1)
	feedEvents(t, rr, flakyPass)

	output := &bytes.Buffer{}
	rr.printFlakinessSummary(output)

	expected := `
===================================================
FAIL(30.0%): example.com/package3.Test5
FAIL(20.0%): example.com/package1.Test1
===================================================
OUTPUT example.com/package3.Test5
===================================================
=== RUN   Test5
    baz_test.go:10: nevermind
--- FAIL: Test5 (0.00s)
===================================================
OUTPUT example.com/package1.Test1
===================================================
=== RUN   Test1
    foo_test.go:6: doing stuff
x =  1
    foo_test.go:8: fail
--- FAIL: Test1 (0.00s)
===================================================
`[1:]
	require.Equal(t, expected, output.String())
}

func strToEvents(t *testing.T, s string) []TestEvent {
	t.Helper()
	result := []TestEvent{}
	decoder := json.NewDecoder(strings.NewReader(s))
	for {
		event := TestEvent{}
		err := decoder.Decode(&event)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		result = append(result, event)
	}
	return result
}

func feedEvents(t *testing.T, rr *runResult, s string) {
	t.Helper()
	events := strToEvents(t, s)
	for _, event := range events {
		rr.processTestEvent(event)
	}
}
