// Copyright 2019-2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package docker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/docker/docker/client"
	runtimeclient "github.com/kinvolk/inspektor-gadget/pkg/container-utils/runtime-client"
)

const (
	Name                   = "docker"
	DefaultEngineAPISocket = "/run/docker.sock"
	DefaultTimeout         = 2 * time.Second
)

// DockerClient implements the ContainerRuntimeClient interface but using the
// Docker Engine API instead of the CRI plugin interface (Dockershim). It was
// necessary because Dockershim does not always use in the same approach of
// CRI-O and Containerd. For instance, Dockershim does not provide the container
// pid1 with the ContainerStatus() call as Containerd and CRI-O do.
type DockerClient struct {
	client    *client.Client
	apiSocket string
}

func NewDockerClient(apiSocket string) (runtimeclient.ContainerRuntimeClient, error) {
	cli, err := client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
		client.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", apiSocket, DefaultTimeout)
		}),
	)
	if err != nil {
		return nil, err
	}
	return &DockerClient{
		client:    cli,
		apiSocket: apiSocket,
	}, nil
}

func (c *DockerClient) PidFromContainerID(containerID string) (int, error) {
	// If ID contains a prefix, it must match the runtime name: "<name>://<ID>"
	split := regexp.MustCompile(`://`).Split(containerID, -1)
	if len(split) == 2 {
		if split[0] != Name {
			return -1, fmt.Errorf("invalid container runtime %q, it should be %q",
				containerID, Name)
		}
		containerID = split[1]
	} else {
		containerID = split[0]
	}

	containerJSON, err := c.client.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return -1, err
	}

	if containerJSON.State == nil {
		return -1, errors.New("container state is nil")
	}

	return containerJSON.State.Pid, nil
}

func (c *DockerClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}

	return nil
}
