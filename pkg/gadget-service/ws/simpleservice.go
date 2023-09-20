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

package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/persistence"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type WebSocketServer struct {
	runtime        runtime.Runtime
	persistenceMgr *persistence.Manager
}

func NewWebServer(runtime runtime.Runtime, manager *persistence.Manager) *WebSocketServer {
	return &WebSocketServer{
		runtime:        runtime,
		persistenceMgr: manager,
	}
}

type sConn struct {
	*websocket.Conn
	srv        *WebSocketServer
	runtime    runtime.Runtime
	gadgets    map[string]*gadgetcontext.GadgetContext
	gadgetLock sync.Mutex
	connLock   sync.Mutex
	encoder    *json.Encoder
}

func (c *sConn) handle() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		command := &Command{}
		err := c.Conn.ReadJSON(command)
		if err != nil {
			log.Warnf("reading JSON: %v", err)
			return
		}
		switch command.Action {
		case "catalog":
			catalog, _ := c.runtime.GetCatalog()
			d, _ := json.Marshal(catalog)
			ev := &GadgetEvent{ID: command.ID, Payload: d}
			c.WriteJSON(ev)
		case "list":
			res, err := c.srv.persistenceMgr.ListPersistentGadgets(ctx, &api.ListPersistentGadgetRequest{})
			if err != nil {
				c.WriteError(command, err)
				continue
			}
			d, _ := protojson.Marshal(res)
			ev := &GadgetEvent{ID: command.ID, Payload: d}
			c.WriteJSON(ev)
		case "delete":
			id := &ID{}
			if err := json.Unmarshal(command.Payload, &id); err != nil {
				c.WriteError(command, err)
				continue
			}
			res, err := c.srv.persistenceMgr.RemovePersistentGadget(ctx, &api.PersistentGadgetId{Id: id.ID})
			if err != nil {
				c.WriteError(command, err)
				continue
			}
			d, _ := protojson.Marshal(res)
			ev := &GadgetEvent{ID: command.ID, Payload: d}
			c.WriteJSON(ev)
		case "start":
			// Create a new gadget
			gadgetStartRequest := &GadgetStartRequest{}
			if err := json.Unmarshal(command.Payload, &gadgetStartRequest); err != nil {
				c.WriteError(command, err)
				continue
			}
			err := c.startGadget(ctx, gadgetStartRequest)
			if err != nil {
				log.Warnf("error from gadget: %v", err)
			}
		case "stop":
			gadgetStopRequest := &GadgetStopRequest{}
			if err := json.Unmarshal(command.Payload, &gadgetStopRequest); err != nil {
				c.WriteError(command, err)
				continue
			}
			err := c.stopGadget(gadgetStopRequest.ID)
			if err != nil {
				c.WriteError(command, err)
			}
		}
	}
}

func (c *sConn) stopGadget(id string) error {
	c.gadgetLock.Lock()
	defer c.gadgetLock.Unlock()

	if gadget, ok := c.gadgets[id]; ok {
		log.Warnf("stopping gadget %s", id)
		gadget.Cancel()
		delete(c.gadgets, id)
	}
	return nil
}

func (c *sConn) WriteError(cmd *Command, err error) error {
	p, _ := json.Marshal(err.Error())
	return c.Conn.WriteJSON(&GadgetEvent{ID: cmd.ID, Type: 255, Payload: p})
}

func (c *sConn) WriteJSON(payload any) error {
	c.connLock.Lock()
	defer c.connLock.Unlock()
	return c.Conn.WriteJSON(payload)
}

func (c *sConn) startGadget(ctx context.Context, request *GadgetStartRequest) error {
	c.gadgetLock.Lock()
	defer c.gadgetLock.Unlock()

	if _, ok := c.gadgets[request.ID]; ok {
		return fmt.Errorf("gadget with ID %q already exists", request.ID)
	}

	logger := logger.NewFromGenericLogger(&Logger{
		send: func(event *GadgetEvent) error {
			event.ID = request.ID
			err := c.WriteJSON(event)
			if err != nil {
				// TODO: Shutdown
			}
			return nil
		},
		level: logger.Level(request.LogLevel),
		// fallbackLogger: s.logger, // TODO
	})

	// Build a gadget context and wire everything up
	gadgetDesc := gadgetregistry.Get(request.GadgetCategory, request.GadgetName)
	if gadgetDesc == nil {
		return fmt.Errorf("gadget not found: %s/%s", request.GadgetCategory, request.GadgetName)
	}

	// Get per gadget operators
	ops := operators.GetOperatorsForGadget(gadgetDesc)
	ops.Init(operators.GlobalParamsCollection())

	operatorParams := ops.ParamCollection()
	err := operatorParams.CopyFromMap(request.Params, "operator.")
	if err != nil {
		return fmt.Errorf("setting operator parameters: %w", err)
	}

	parser := gadgetDesc.Parser()

	runtimeParams := c.runtime.ParamDescs().ToParams()
	err = runtimeParams.CopyFromMap(request.Params, "runtime.")
	if err != nil {
		return fmt.Errorf("setting runtime parameters: %w", err)
	}

	gadgetParamDescs := gadgetDesc.ParamDescs()
	gadgetParamDescs.Add(gadgets.GadgetParams(gadgetDesc, parser)...)
	gadgetParams := gadgetParamDescs.ToParams()
	err = gadgetParams.CopyFromMap(request.Params, "")
	if err != nil {
		return fmt.Errorf("setting gadget parameters: %w", err)
	}

	if parser != nil {
		// Send metadata first
		gadgetMetadata, err := json.Marshal(parser.GetColumns())
		if err != nil {
			return fmt.Errorf("marshalling metadata: %v", err)
		}
		c.WriteJSON(&GadgetEvent{
			ID:      request.ID,
			Type:    api.EventTypeGadgetMetadata,
			Payload: gadgetMetadata,
		})

		f := parser.GetJSONFormatter()
		parser.SetLogCallback(logger.Logf)
		f.SetEventCallback(func(data string) {
			event := &GadgetEvent{
				ID:      request.ID,
				Type:    api.EventTypeGadgetPayload,
				Payload: json.RawMessage(data),
			}
			c.WriteJSON(event)
		})
		parser.SetEventCallback(f.EventHandlerFunc())
		parser.SetEventCallback(f.EventHandlerFuncArray())
	}

	// Assign a unique ID - this will be used in the future
	runID := uuid.New().String()

	// Create new Gadget Context
	gadgetCtx := gadgetcontext.New(
		ctx,
		runID,
		c.runtime,
		runtimeParams,
		gadgetDesc,
		gadgetParams,
		[]string{}, // TODO
		operatorParams,
		parser,
		logger,
		time.Duration(request.Timeout),
	)

	c.gadgets[request.ID] = gadgetCtx

	log.Warnf("started gadget %s (%s/%s)", request.ID, request.GadgetCategory, request.GadgetName)

	go func() {
		defer gadgetCtx.Cancel()
		defer func() {
			c.gadgetLock.Lock()
			defer c.gadgetLock.Unlock()

			delete(c.gadgets, request.ID)
		}()

		// Hand over to runtime
		results, err := c.runtime.RunGadget(gadgetCtx)
		if err != nil {
			// return fmt.Errorf("running gadget: %w", err)
		}

		// Send result, if any
		for _, result := range results {
			// TODO: when used with fan-out, we need to add the node in here
			event := &GadgetEvent{
				ID:      request.ID,
				Type:    api.EventTypeGadgetResult,
				Payload: result.Payload,
			}
			c.WriteJSON(event)
		}
	}()

	return nil
}

func (s *WebSocketServer) Run(network, addr string) error {
	srv := http.NewServeMux()
	srv.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Print("upgrade:", err)
			return
		}
		defer c.Close()
		(&sConn{
			Conn:    c,
			srv:     s,
			runtime: s.runtime,
			gadgets: map[string]*gadgetcontext.GadgetContext{},
		}).handle()
	})
	return http.ListenAndServe(":9999", srv)
}
