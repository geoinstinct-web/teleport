/*
Copyright 2020 Gravitational, Inc.
Copyright 2009 The Go Authors.

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

package scp

import (
	"os"
	"syscall"
	"time"
)

// Source: os/types_windows.go
func atime(fi os.FileInfo) time.Time {
	return time.Unix(0, fi.Sys().(*syscall.Win32FileAttributeData).LastAccessTime.Nanoseconds())
}
