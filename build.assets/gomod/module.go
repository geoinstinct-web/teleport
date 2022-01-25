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

package gomod

import (
	"os"
	"path/filepath"

	"github.com/gravitational/trace"
	"golang.org/x/mod/modfile"
)

// GetImportPath gets the module's import path from its go.mod file
func GetImportPath(dir string) (string, error) {
	modPath := filepath.Join(dir, "go.mod")
	bts, err := os.ReadFile(modPath)
	if err != nil {
		return "", trace.Wrap(err)
	}
	modFile, err := modfile.Parse(modPath, bts, nil /* fix */)
	if err != nil {
		return "", trace.Wrap(err)
	}
	if modFile.Module == nil || modFile.Module.Mod.Path == "" {
		return "", trace.NotFound("could not find mod path for %v", dir)
	}
	return modFile.Module.Mod.Path, nil
}
