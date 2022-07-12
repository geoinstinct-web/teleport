// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestAliasRunner(t *testing.T) *aliasRunner {
	return &aliasRunner{
		getEnv: func(key string) string {
			t.Fatalf("calling uninitialized function 'getEnv(key=%q)'", key)
			return ""
		},
		setEnv: func(key, value string) error {
			t.Fatalf("calling uninitialized function 'setEnv(key=%q,value=%q)'", key, value)
			return nil
		},
		runTshMain: func(ctx context.Context, args []string, opts ...cliOption) error {
			t.Fatalf("calling uninitialized function 'runTshMain(ctx=%v,args=%v,opts=%v)'", ctx, args, opts)
			return nil
		},
		runExternalCommand: func(cmd *exec.Cmd) error {
			t.Fatalf("calling uninitialized function 'runExternalCommand(cmd=%v)'", cmd)
			return nil
		},
		aliases: nil,
	}
}

func Test_expandAliasDefinition(t *testing.T) {
	tests := []struct {
		name      string
		aliasDef  string
		argsGiven []string
		want      []string
		wantErr   bool
	}{
		{
			name:      "empty",
			aliasDef:  "",
			argsGiven: nil,
			want:      []string{},
			wantErr:   false,
		},
		{
			name:      "empty alias, append all",
			aliasDef:  "",
			argsGiven: []string{"foo", "bar", "baz"},
			want:      []string{"foo", "bar", "baz"},
			wantErr:   false,
		},
		{
			name:      "append unused elems",
			aliasDef:  "$3 $0",
			argsGiven: []string{"arg0", "arg1", "arg2", "arg3"},
			want:      []string{"arg3", "arg0", "arg1", "arg2"},
			wantErr:   false,
		},
		{
			name:      "no references, append args",
			aliasDef:  "foo1 foo2 foo3",
			argsGiven: []string{"arg1", "arg2", "arg3"},
			want:      []string{"foo1", "foo2", "foo3", "arg1", "arg2", "arg3"},
			wantErr:   false,
		},
		{
			name:      "valid references",
			aliasDef:  "refFoo $0 refBar $1",
			argsGiven: []string{"foo", "bar"},
			want:      []string{"refFoo", "foo", "refBar", "bar"},
			wantErr:   false,
		},
		{
			name:      "out of range reference",
			aliasDef:  "refFoo $0 refBar $1",
			argsGiven: []string{"foo"},
			wantErr:   true,
		},
		{
			name:      "ignore negative reference",
			aliasDef:  "$-100",
			argsGiven: nil,
			want:      []string{"$-100"},
			wantErr:   false,
		},
		{
			name:      "unknown references fail",
			argsGiven: nil,
			aliasDef:  "$100 200 300",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expandAliasDefinition(tt.aliasDef, tt.argsGiven)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}
		})
	}
}

func Test_findAliasCommand(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantAlias string
		wantArgs  []string
	}{
		{
			name:      "empty args not found",
			args:      nil,
			wantAlias: "",
			wantArgs:  nil,
		},
		{
			name:      "only options, not found",
			args:      []string{"--foo", "--bar", "-baz", "--"},
			wantAlias: "",
			wantArgs:  []string{"--foo", "--bar", "-baz", "--"},
		},
		{
			name:      "first place",
			args:      []string{"login", "--foo", "--bar"},
			wantAlias: "login",
			wantArgs:  []string{"--foo", "--bar"},
		},
		{
			name:      "second place",
			args:      []string{"--foo", "login", "--bar"},
			wantAlias: "login",
			wantArgs:  []string{"--foo", "--bar"},
		},
		{
			name:      "last place",
			args:      []string{"--foo", "--bar", "login"},
			wantAlias: "login",
			wantArgs:  []string{"--foo", "--bar"},
		},
		{
			name:      "last place, empty arg thrown in",
			args:      []string{"--foo", "--bar", "", "login"},
			wantAlias: "login",
			wantArgs:  []string{"--foo", "--bar", ""},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alias, args := findAliasCommand(tt.args)
			require.Equal(t, tt.wantAlias, alias)
			require.Equal(t, tt.wantArgs, args)
		})
	}
}

func Test_getSeenAliases(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want []string
	}{
		{
			name: "empty",
			env:  nil,
			want: nil,
		},
		{
			name: "commas",
			env:  map[string]string{tshAliasEnvKey: ",,,"},
			want: nil,
		},
		{
			name: "few values",
			env:  map[string]string{tshAliasEnvKey: "foo,bar,baz,,,"},
			want: []string{"foo", "bar", "baz"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ar := newTestAliasRunner(t)
			ar.getEnv = func(key string) string {
				val := tt.env[key]
				return val
			}
			require.Equal(t, tt.want, ar.getSeenAliases())
		})
	}
}

func Test_markAliasSeen(t *testing.T) {
	tests := []struct {
		name   string
		envIn  map[string]string
		alias  string
		envOut map[string]string
	}{
		{
			name:   "empty",
			envIn:  map[string]string{},
			alias:  "foo",
			envOut: map[string]string{tshAliasEnvKey: "foo"},
		},
		{
			name:   "commas",
			envIn:  map[string]string{tshAliasEnvKey: ",,,"},
			alias:  "foo",
			envOut: map[string]string{tshAliasEnvKey: "foo"},
		},
		{
			name:   "a few values",
			envIn:  map[string]string{tshAliasEnvKey: "foo,bar,baz,,,"},
			alias:  "foo",
			envOut: map[string]string{tshAliasEnvKey: "foo,bar,baz,foo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ar := newTestAliasRunner(t)
			ar.getEnv = func(key string) string {
				val := tt.envIn[key]
				return val
			}
			ar.setEnv = func(key, value string) error {
				tt.envIn[key] = value
				return nil
			}

			require.NoError(t, ar.markAliasSeen(tt.alias))
			require.Equal(t, tt.envOut, tt.envIn)
		})
	}
}

func Test_getAliasDefinition(t *testing.T) {
	tests := []struct {
		name      string
		seen      []string
		aliasDefs map[string]string
		alias     string
		wantOk    bool
		wantDef   string
	}{
		{
			name:      "empty env, no match",
			seen:      []string{},
			aliasDefs: map[string]string{},
			alias:     "foo",
			wantOk:    false,
			wantDef:   "",
		},
		{
			name:      "empty env, match",
			seen:      []string{},
			aliasDefs: map[string]string{"foo": "bar baz"},
			alias:     "foo",
			wantOk:    true,
			wantDef:   "bar baz",
		},
		{
			name:      "seen alias, ignored",
			seen:      []string{"foo"},
			aliasDefs: map[string]string{"foo": "bar baz"},
			alias:     "foo",
			wantOk:    false,
			wantDef:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ar := newTestAliasRunner(t)
			ar.getEnv = func(key string) string {
				if key == tshAliasEnvKey {
					return strings.Join(tt.seen, ",")
				}
				return ""
			}
			ar.aliases = tt.aliasDefs

			gotOk, gotDefinition := ar.getAliasDefinition(tt.alias)
			require.Equal(t, tt.wantOk, gotOk)
			require.Equal(t, tt.wantDef, gotDefinition)
		})
	}
}

func Test_runAliasCommand(t *testing.T) {
	selfExe, err := os.Executable()
	require.NoError(t, err)

	mainCalls := 0
	externalCalls := 0

	ar := &aliasRunner{
		runTshMain: func(ctx context.Context, args []string, opts ...cliOption) error {
			mainCalls += 1
			return nil
		},
		runExternalCommand: func(cmd *exec.Cmd) error {
			externalCalls += 1
			return nil
		},
	}

	// Run() call
	err = ar.runAliasCommand(context.Background(), selfExe, selfExe, []string{"--debug", "login"})
	require.NoError(t, err)
	require.Equal(t, 1, mainCalls)
	require.Equal(t, 0, externalCalls)

	// external command
	err = ar.runAliasCommand(context.Background(), selfExe, "sh", []string{"echo", "hello world"})
	require.NoError(t, err)
	require.Equal(t, 1, mainCalls)
	require.Equal(t, 1, externalCalls)
}
