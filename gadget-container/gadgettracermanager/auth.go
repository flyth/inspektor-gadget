// Copyright 2022 The Inspektor Gadget authors
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

package main

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	v1 "k8s.io/api/core/v1"
	client2 "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	cert_helpers "github.com/inspektor-gadget/inspektor-gadget/internal/cert-helpers"
)

func tokenInterceptor(grpcToken string) func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
		}
		auth, ok := md["authorization"]
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "missing token")
		}
		token := strings.TrimPrefix(auth[0], "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(grpcToken)) != 1 {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token")
		}
		return handler(ctx, req)
	}
}

func streamInterceptor() func(srv interface{}, serverStream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return func(srv interface{}, serverStream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		p, ok := peer.FromContext(serverStream.Context())
		if !ok {
			return status.Errorf(codes.Unauthenticated, "invalid certificate")
		}
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		log.Infof("stream request from %s", subject)
		return handler(srv, serverStream)
	}
}

func unaryInterceptor() func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
		p, ok := peer.FromContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "invalid certificate")
		}
		tlsInfo := p.AuthInfo.(credentials.TLSInfo)
		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		log.Infof("request from %s", subject)
		return handler(ctx, req)
	}
}

func loadCA(mgr manager.Manager) ([]byte, []byte, error) {
	obj := &v1.Secret{}
	err := mgr.GetClient().Get(context.Background(), client2.ObjectKey{
		Namespace: "gadget",
		Name:      "ca",
	}, obj)
	if err != nil {
		return nil, nil, fmt.Errorf("get gadget CA secret: %w", err)
	}
	return obj.Data["cert"], obj.Data["key"], nil
}

func loadOrGenerateCertificate(node string, mgr manager.Manager) ([]byte, []byte, *x509.Certificate, error) {
	caCert, _, err := loadCA(mgr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("get CA: %w", err)
	}

	ca, err := x509.ParseCertificate(caCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse CA: %w", err)
	}

	cert, privateKey, err := generateCertificate(node, mgr)
	return cert, privateKey, ca, err
}

func generateCertificate(node string, mgr manager.Manager) ([]byte, []byte, error) {
	caCert, caPrivateKey, err := loadCA(mgr)
	if err != nil {
		return nil, nil, fmt.Errorf("get CA: %w", err)
	}

	cert, privateKey, err := cert_helpers.GenerateCertificate(node, x509.ExtKeyUsageServerAuth, cert_helpers.Year*10, caCert, caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server key: %w", err)
	}

	return cert, privateKey, nil
}
