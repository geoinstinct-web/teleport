/*
Copyright 2021 Gravitational, Inc.

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

package bot

import (
	"context"
	"log"
	"strings"

	"github.com/gravitational/trace"
)

// Label parses the content of the PR (branch name, files, etc) and sets
// appropriate labels.
func (b *Bot) Label(ctx context.Context) error {
	labels, err := b.labels(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	err = b.c.GitHub.AddLabels(ctx,
		b.c.Environment.Organization,
		b.c.Environment.Repository,
		b.c.Environment.Number,
		labels)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (b *Bot) labels(ctx context.Context) ([]string, error) {
	var labels []string

	// The branch name is unsafe, but here we are simply adding a label.
	if strings.HasPrefix(b.c.Environment.UnsafeBranch, "branch/") {
		log.Println("Label: Found backport branch.")
		labels = append(labels, "backport")
	}

	files, err := b.c.GitHub.ListFiles(ctx,
		b.c.Environment.Organization,
		b.c.Environment.Repository,
		b.c.Environment.Number)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	for _, file := range files {
		for k, v := range prefixes {
			if strings.HasPrefix(file, k) {
				log.Printf("Label: Found prefix %v, attaching labels: %v.", k, v)
				labels = append(labels, v...)
			}
		}
		for k, v := range suffixes {
			if strings.HasSuffix(file, k) {
				log.Printf("Label: Found suffix %v, attaching labels: %v.", k, v)
				labels = append(labels, v...)
			}
		}
	}

	return deduplicate(labels), nil
}

func deduplicate(s []string) []string {
	m := map[string]bool{}
	for _, v := range s {
		m[v] = true
	}

	var out []string
	for k, _ := range m {
		out = append(out, k)
	}

	return out
}

var prefixes map[string][]string = map[string][]string{
	"bpf/":                []string{"bpf"},
	"docs/":               []string{"documentation"},
	"rfd/":                []string{"documentation", "rfd"},
	"examples/chart":      []string{"helm"},
	"lib/bpf/":            []string{"bpf"},
	"lib/events":          []string{"audit-log"},
	"lib/kube":            []string{"kubernetes"},
	"lib/srv/desktop":     []string{"desktop-access"},
	"lib/srv/desktop/rdp": []string{"desktop-access", "rdp"},
	"lib/srv/app/":        []string{"application-access"},
	"lib/srv/db":          []string{"database-access"},
	"lib/web/desktop.go":  []string{"desktop-access"},
	"tool/tctl/":          []string{"tctl"},
	"tool/tsh/":           []string{"tsh"},
}

var suffixes map[string][]string = map[string][]string{
	".md":  []string{"documentation"},
	".mdx": []string{"documentation"},
}
