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

package upgradewindow

import (
	"fmt"
	"strings"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/utils"
)

// EncodeKubeControllerSchedule converts an agent upgrade schedule to the file format
// expected by the kuberenets upgrade controller.
func EncodeKubeControllerSchedule(schedule types.AgentUpgradeSchedule) (string, error) {
	b, err := utils.FastMarshal(&schedule)
	if err != nil {
		return "", trace.Errorf("failed to encode kube controller schedule: %v", err)
	}

	return string(b), nil
}

// unitScheduleHeader is the first line in the systemd unit upgrader schedule. The teleport-upgrade
// script invoked by the unit ignores all lines starting with '# '.
const unitScheduleHeader = "# generated by teleport\n"

// EncodeSystemdUnitSchedule converts an agent upgrade schedule to the file format
// expected by the teleport-upgrade script.
func EncodeSystemdUnitSchedule(schedule types.AgentUpgradeSchedule) (string, error) {
	if len(schedule.Windows) == 0 {
		return "", trace.BadParameter("cannot encode empty schedule")
	}

	var builder strings.Builder
	builder.WriteString(unitScheduleHeader)
	for _, window := range schedule.Windows {
		// upgrade windows are encoded as a pair of space-separated unix timestamps.
		fmt.Fprintf(&builder, "%d %d\n", window.Start.Unix(), window.Stop.Unix())
	}

	return builder.String(), nil
}
