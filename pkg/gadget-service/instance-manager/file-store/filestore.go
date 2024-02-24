// Copyright 2024 The Inspektor Gadget authors
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

package filestore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/moby/pkg/namesgenerator"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	instancemanager "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/instance-manager"
)

var GadgetFilePath = "/var/lib/ig"

type fileStore struct {
	api.OCIGadgetInstanceManagerStoreServer
	mgr *instancemanager.Manager
}

func New(mgr *instancemanager.Manager) (instancemanager.Store, error) {
	fs := &fileStore{
		mgr: mgr,
	}
	err := fs.init()
	if err != nil {
		return nil, err
	}
	return fs, nil
}

func (s *fileStore) init() error {
	err := os.MkdirAll(GadgetFilePath, 0o744)
	if err != nil && errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating directory %q: %w", GadgetFilePath, err)
	}

	gadgets, err := s.getGadgets()
	if err != nil {
		return fmt.Errorf("reading existing gadgets: %w", err)
	}

	for _, gadget := range gadgets {
		log.Infof("loading gadget instance %q", gadget.GadgetInstance.Id)
		err := s.mgr.RunOCIGadget(gadget.GadgetInstance.Id, gadget.GadgetInstance.RunRequest)
		if err != nil {
			return fmt.Errorf("loading gadgets: %w", err)
		}
	}
	return nil
}

// loadGadgetFile loads a gadget configuration from a file
func loadGadgetFile(filename string) (*api.InstallOCIGadgetInstanceRequest, error) {
	// TODO: do we need to sanitize?
	blob, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", filename, err)
	}
	gadget := &api.InstallOCIGadgetInstanceRequest{}
	err = protojson.Unmarshal(blob, gadget)
	if err != nil {
		return nil, fmt.Errorf("unmarshal gadget info for file %q: %w", filename, err)
	}
	return gadget, nil
}

// getGadgets returns a list of all installed gadget configurations
func (s *fileStore) getGadgets() ([]*api.InstallOCIGadgetInstanceRequest, error) {
	files, err := os.ReadDir(GadgetFilePath)
	if err != nil {
		return nil, fmt.Errorf("reading gadgets: %w", err)
	}

	res := make([]*api.InstallOCIGadgetInstanceRequest, 0)
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".gadget") {
			continue
		}
		gadget, err := loadGadgetFile(filepath.Join(GadgetFilePath, file.Name()))
		if err != nil {
			log.Warnf("could not read gadget file: %v", err)
			continue
		}
		res = append(res, gadget)
	}
	return res, nil
}

func (s *fileStore) InstallOCIGadgetInstance(ctx context.Context, req *api.InstallOCIGadgetInstanceRequest) (*api.InstallOCIGadgetInstanceResponse, error) {
	idBytes := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, idBytes)
	if err != nil {
		return nil, fmt.Errorf("could not build gadget id")
	}
	id := hex.EncodeToString(idBytes)
	req.GadgetInstance.Id = id

	if req.GadgetInstance.Name == "" {
		req.GadgetInstance.Name = namesgenerator.GetRandomName(0)
	}

	// Store to gadget file
	gadgetBlob, _ := protojson.Marshal(req)
	filename := filepath.Join(GadgetFilePath, fmt.Sprintf("%s.gadget", id))
	err = os.WriteFile(filename, gadgetBlob, 0o644)
	if err != nil {
		return nil, fmt.Errorf("storing gadget information: %w", err)
	}

	log.Debugf("installing new gadget %q", id)
	s.mgr.RunOCIGadget(req.GadgetInstance.Id, req.GadgetInstance.RunRequest)
	return &api.InstallOCIGadgetInstanceResponse{
		Result:         0,
		GadgetInstance: req.GadgetInstance,
	}, nil
}

func (s *fileStore) ListOCIGadgetInstances(ctx context.Context, request *api.ListOCIGadgetInstancesRequest) (*api.ListOCIGadgetInstanceResponse, error) {
	gadgets, err := s.getGadgets()
	if err != nil {
		return nil, fmt.Errorf("loading gadgets: %w", err)
	}
	gadgetInstances := make([]*api.OCIGadgetInstance, 0, len(gadgets))
	for _, gadget := range gadgets {
		gadgetInstances = append(gadgetInstances, gadget.GadgetInstance)
	}
	return &api.ListOCIGadgetInstanceResponse{GadgetInstances: gadgetInstances}, nil
}

func (s *fileStore) RemoveOCIGadgetInstance(ctx context.Context, req *api.OCIGadgetInstanceId) (*api.StatusResponse, error) {
	path := filepath.Join(GadgetFilePath, fmt.Sprintf("%s.gadget", req.Id))
	_, err := loadGadgetFile(path)
	if err != nil {
		return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
	}

	log.Debugf("removing gadget %q", req.Id)
	err = os.Remove(path)

	s.mgr.RemoveOCIGadget(req.Id)

	if err != nil {
		return &api.StatusResponse{Result: 1, Message: err.Error()}, nil
	}
	return &api.StatusResponse{Result: 0}, nil
}

func (s *fileStore) ControlOCIInstance(ctx context.Context, ctrl *api.OCIGadgetControlRequest) (*api.StatusResponse, error) {
	return nil, fmt.Errorf("unimplemented")
}
