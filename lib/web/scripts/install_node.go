/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package scripts

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/gravitational/trace"
	"gopkg.in/yaml.v3"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils"
)

// ErrorBashScript is used to display friendly error message when
// there is an error prepping the actual script.
var ErrorBashScript = []byte(`
#!/bin/sh
echo -e "An error has occurred. \nThe token may be expired or invalid. \nPlease check log for further details."
exit 1
`)

// InstallNodeBashScript is the script that will run on user's machine
// to install teleport and join a teleport cluster.
//
//go:embed node-join/install.sh
var installNodeBashScript string

var InstallNodeBashScript = template.Must(template.New("nodejoin").Parse(installNodeBashScript))

// MarshalLabelsYAML returns a list of strings, each one containing a
// label key and list of value's pair.
// This is used to create yaml sections within the join scripts.
//
// The arg `extraListIndent` allows adding `extra` indent space on
// top of the default space already used, for the default yaml listing
// format (the listing values with the dashes). If `extraListIndent`
// is zero, it's equivalent to using default space only (which is 4 spaces).
func MarshalLabelsYAML(resourceMatcherLabels types.Labels, extraListIndent int) ([]string, error) {
	if len(resourceMatcherLabels) == 0 {
		return []string{"{}"}, nil
	}

	ret := []string{}

	// Consistently iterate over fields
	labelKeys := make([]string, 0, len(resourceMatcherLabels))
	for k := range resourceMatcherLabels {
		labelKeys = append(labelKeys, k)
	}

	sort.Strings(labelKeys)

	for _, labelName := range labelKeys {
		labelValues := resourceMatcherLabels[labelName]
		bs, err := yaml.Marshal(map[string]utils.Strings{labelName: labelValues})
		if err != nil {
			return nil, trace.Wrap(err)
		}

		labelStr := strings.TrimSpace(string(bs))
		if len(labelValues) > 1 && extraListIndent > 0 {
			labelStr = addExtraListIndentToYAMLLabelStr(labelStr, extraListIndent)
		}

		ret = append(ret, labelStr)
	}

	return ret, nil
}

func addExtraListIndentToYAMLLabelStr(labelStr string, indent int) string {
	words := strings.Split(labelStr, "\n")
	// Skip the first word, since that is the label key.
	// Add extra spaces defined by `yamlListIndent` arg.
	for i := 1; i < len(words); i++ {
		words[i] = fmt.Sprintf("%s%s", strings.Repeat(" ", indent), words[i])
	}

	return strings.Join(words, "\n")
}
