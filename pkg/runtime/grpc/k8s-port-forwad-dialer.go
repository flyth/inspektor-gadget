// Copyright 2023 The Inspektor Gadget authors
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

package grpcruntime

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
)

const (
	GadgetServiceSocket = "/run/gadgetservice.socket"
)

type k8sPortForwardConn struct {
	conn    httpstream.Connection
	stream  httpstream.Stream
	podName string
}

// NewK8SPortForwardConn connects to a remote tcp socket using the Forward functionality of the Kubernetes API server.
// This cannot handle connections to unix sockets.
func NewK8SPortForwardConn(ctx context.Context, pod v1.Pod, timeout time.Duration) (net.Conn, error) {
	conn := &k8sPortForwardConn{}

	config, err := utils.KubernetesConfigFlags.ToRESTConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to creating RESTConfig: %w", err)
	}

	conn.podName = pod.Name
	config.Timeout = timeout

	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return nil, fmt.Errorf("creating roundtripper: %w", err)
	}

	targetURL, err := url.Parse(config.Host)
	if err != nil {
		return nil, fmt.Errorf("parsing restConfig.Host: %w", err)
	}

	targetURL.Path = path.Join(
		"api", "v1",
		"namespaces", "gadget",
		"pods", conn.podName,
		"portforward",
	)

	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, targetURL)

	xconn, _, err := dialer.Dial(portforward.PortForwardProtocolV1Name)
	if err != nil {
		return nil, err
	}

	conn.conn = xconn

	// create error stream
	headers := http.Header{}
	headers.Set(v1.StreamType, v1.StreamTypeError)
	headers.Set(v1.PortHeader, "/run/gadgettracermanager.socket") // fmt.Sprintf("%d", 6543))
	headers.Set(v1.PortForwardRequestIDHeader, strconv.Itoa(1))
	errorStream, err := xconn.CreateStream(headers)
	if err != nil {
		return nil, fmt.Errorf("creating error stream for port forward: %w", err)
	}
	// we're not writing to this stream
	errorStream.Close()

	errorChan := make(chan error)
	go func() {
		message, err := io.ReadAll(errorStream)
		switch {
		case err != nil:
			errorChan <- fmt.Errorf("error reading from error stream: %v", err)
		case len(message) > 0:
			errorChan <- fmt.Errorf("an error occurred forwarding: %v", string(message))
		}
		close(errorChan)
	}()

	// create data stream
	headers.Set(v1.StreamType, v1.StreamTypeData)
	dataStream, err := xconn.CreateStream(headers)
	if err != nil {
		return nil, fmt.Errorf("creating data stream for port forward")
	}

	conn.stream = dataStream
	return conn, nil
}

func (k *k8sPortForwardConn) Read(b []byte) (n int, err error) {
	return k.stream.Read(b)
}

func (k *k8sPortForwardConn) Write(b []byte) (n int, err error) {
	return k.stream.Write(b)
}

func (k *k8sPortForwardConn) Close() error {
	k.stream.Close()
	return k.conn.Close()
}

func (k *k8sPortForwardConn) LocalAddr() net.Addr {
	return &k8sAddress{}
}

func (k *k8sPortForwardConn) RemoteAddr() net.Addr {
	return &k8sAddress{podName: k.podName}
}

func (k *k8sPortForwardConn) SetDeadline(t time.Time) error {
	return nil
}

func (k *k8sPortForwardConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (k *k8sPortForwardConn) SetWriteDeadline(t time.Time) error {
	return nil
}
