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

package controller

import (
	"github.com/gravitational/trace"
	v1 "k8s.io/api/core/v1"
)

func getContainerImageFromPodSpec(spec v1.PodSpec, container string) (string, error) {
	for _, containerSpec := range spec.Containers {
		if containerSpec.Name == container {
			return containerSpec.Image, nil
		}
	}
	return "", trace.NotFound("container %q not found in podSpec", container)
}

func setContainerImageFromPodSpec(spec *v1.PodSpec, container, image string) error {
	for i, containerSpec := range spec.Containers {
		if containerSpec.Name == container {
			spec.Containers[i].Image = image
			return nil
		}
	}
	return trace.NotFound("container %q not found in podSpec", container)
}
