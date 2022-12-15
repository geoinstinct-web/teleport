/*
Copyright 2022 Gravitational, Inc.

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

package partial

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func constraint(expr string) []Constraint {
	return []Constraint{{
		Allow: true,
		Expr:  expr,
	}}
}

// TestSolverIntEq tests solving for a single integer equality.
func TestSolverIntEq(t *testing.T) {
	state := NewSolver()
	x, err := state.PartialSolveForAll(context.Background(), constraint("x == 7"), func(s []string) any {
		return nil
	}, "x", TypeInt, 1)

	require.NoError(t, err)
	require.Len(t, x, 1)
	require.Equal(t, "7", x[0].String())
}

// TestSolverFn tests custom functions
func TestSolverFn(t *testing.T) {
	state := NewSolver()
	x, err := state.PartialSolveForAll(context.Background(), constraint("upper(x) == \"BANANA\""), func(s []string) any {
		return nil
	}, "x", TypeString, 2)

	require.NoError(t, err)

	s := make([]string, len(x))
	for i, v := range x {
		s[i] = v.String()
	}
	require.ElementsMatch(t, []string{"\"BananA\"", "\"BAnanA\""}, s)
}

// TestSolverStringExpMultiSolution tests solving against a string equality expression with two solutions.
func TestSolverStringExpMultiSolution(t *testing.T) {
	resolver := func(s []string) any {
		if len(s) > 0 && s[0] == "jimsName" {
			return "jims"
		}
		return nil
	}

	state := NewSolver()
	x, err := state.PartialSolveForAll(context.Background(), constraint("x == \"blah\" || x == \"root\" || x == jimsName"), resolver, "x", TypeString, 3)
	require.NoError(t, err)

	s := make([]string, len(x))
	for i, v := range x {
		s[i] = v.String()
	}
	require.ElementsMatch(t, []string{`"blah"`, `"root"`, `"jims"`}, s)
}

// BenchmarkSolverStringExpMultiSolutionCached benchmarks TestSolverStringExpMultiSolution for performance monitoring.
// Example result (M1 Macbook 14 Pro 2021):
// BenchmarkSolverStringExpMultiSolutionCached-10    	     168	   7087695 ns/op
func BenchmarkSolverStringExpMultiSolutionCached(b *testing.B) {
	resolver := func(s []string) any {
		if len(s) > 0 && s[0] == "jimsName" {
			return "jims"
		}
		return nil
	}

	state := NewSolver()

	for i := 0; i < b.N; i++ {
		x, err := state.PartialSolveForAll(context.Background(), constraint("x == \"blah\" || x == \"root\" || x == jimsName"), resolver, "x", TypeString, 3)

		if err != nil {
			b.Fatal(err)
		}

		s := make([]string, len(x))
		for i, v := range x {
			s[i] = v.String()
		}
		require.ElementsMatch(b, []string{`"blah"`, `"root"`, `"jims"`}, s)
	}
}

// BenchmarkSolverStringExpMultiSolution benchmarks TestSolverStringExpMultiSolution for performance monitoring.
// Example result (M1 Macbook 14 Pro 2021):
// BenchmarkSolverStringExpMultiSolution-10          	     124	   9534720 ns/op
func BenchmarkSolverStringExpMultiSolution(b *testing.B) {
	resolver := func(s []string) any {
		if len(s) > 0 && s[0] == "jimsName" {
			return "jims"
		}
		return nil
	}

	for i := 0; i < b.N; i++ {
		state := NewSolver()
		x, err := state.PartialSolveForAll(context.Background(), constraint("x == \"blah\" || x == \"root\" || x == jimsName"), resolver, "x", TypeString, 3)

		if err != nil {
			b.Fatal(err)
		}

		s := make([]string, len(x))
		for i, v := range x {
			s[i] = v.String()
		}
		require.ElementsMatch(b, []string{`"blah"`, `"root"`, `"jims"`}, s)
	}
}
