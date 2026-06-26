// Copyright 2024-2025 The Inspektor Gadget authors
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

package gadgetservice

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func (s *Service) initOperators() error {
	for op, globalParams := range s.operators {
		err := op.Init(globalParams)
		if err != nil {
			return fmt.Errorf("initializing operator %s: %w", op.Name(), err)
		}
	}
	return nil
}

func (s *Service) GetOperatorMap() map[operators.DataOperator]*params.Params {
	return s.operators
}

func (s *Service) GetGadgetInfo(ctx context.Context, req *api.GetGadgetInfoRequest) (*api.GetGadgetInfoResponse, error) {
	metricAttribs := attribute.NewSet(
		attribute.KeyValue{Key: "gadget_image", Value: attribute.StringValue(req.ImageName)},
	)
	defer s.ctrGetGadgetInfo.Add(context.Background(), 1, metric.WithAttributeSet(metricAttribs))

	if req.Version != api.VersionGadgetInfo {
		return nil, fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetInfo, req.Version)
	}

	p, ok := peer.FromContext(ctx)
	if ok && p.AuthInfo != nil {
		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			return nil, fmt.Errorf("authentication information is not TLS: %v", p.AuthInfo)
		}

		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		s.logger.Infof("[%s] GetGadgetInfo(%q)", subject, req.ImageName)
	}

	if req.Flags&api.GadgetInfoRequestFlagUseInstance != 0 {
		if s.instanceMgr == nil {
			return nil, fmt.Errorf("instance manager not initialized")
		}
		gi := s.instanceMgr.LookupInstance(req.ImageName)
		if gi == nil {
			return nil, fmt.Errorf("instance %s not found", req.ImageName)
		}
		gadgetInfo, err := gi.GadgetInfo()
		if err != nil {
			return nil, err
		}
		return &api.GetGadgetInfoResponse{GadgetInfo: gadgetInfo}, nil
	}

	// Get all available operators
	ops := make([]operators.DataOperator, 0)
	for op := range s.operators {
		ops = append(ops, op)
	}

	gadgetCtx := gadgetcontext.New(
		ctx,
		req.ImageName,
		gadgetcontext.WithDataOperators(ops...),
		gadgetcontext.WithAsRemoteCall(true),
		gadgetcontext.IncludeExtraInfo(req.RequestExtraInfo),
	)

	gi, err := s.runtime.GetGadgetInfo(gadgetCtx, s.runtime.ParamDescs().ToParams(), req.ParamValues)
	if err != nil {
		return nil, fmt.Errorf("getting gadget info: %w", err)
	}
	return &api.GetGadgetInfoResponse{GadgetInfo: gi}, nil
}

func (s *Service) RunGadget(runGadget api.GadgetManager_RunGadgetServer) error {
	ctrl, err := runGadget.Recv()
	if err != nil {
		return err
	}

	attachRequest := ctrl.GetAttachRequest()
	if attachRequest != nil {
		if attachRequest.Version != api.VersionGadgetRunProtocol {
			return fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetRunProtocol, attachRequest.Version)
		}
		if s.instanceMgr == nil {
			return errors.New("instance manager not initialized")
		}

		s.ctrAttachGadget.Add(context.Background(), 1)
		return s.instanceMgr.AttachToGadgetInstance(attachRequest.Id, runGadget)
	}

	ociRequest := ctrl.GetRunRequest()
	if ociRequest == nil {
		return fmt.Errorf("expected first control message to be gadget run request")
	}

	metricAttribs := attribute.NewSet(
		attribute.KeyValue{Key: "gadget_image", Value: attribute.StringValue(ociRequest.ImageName)},
	)
	defer s.ctrRunGadget.Add(context.Background(), 1, metric.WithAttributeSet(metricAttribs))

	p, ok := peer.FromContext(runGadget.Context())
	if ok && p.AuthInfo != nil {
		tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
		if !ok {
			return fmt.Errorf("authentication information are not TLS: %v", p.AuthInfo)
		}

		subject := tlsInfo.State.VerifiedChains[0][0].Subject
		s.logger.Infof("[%s] RunGadget(%q)", subject, ociRequest.ImageName)
	}

	if ociRequest.Version != api.VersionGadgetRunProtocol {
		return fmt.Errorf("expected version to be %d, got %d", api.VersionGadgetRunProtocol, ociRequest.Version)
	}

	// Create payload buffer
	outputBuffer := make(chan *api.GadgetEvent, s.eventBufferLength)

	// Recycle the GadgetEvent wrappers together with their marshaled-payload
	// buffers (the buffer stays attached as event.Payload). proto.Marshal would
	// otherwise allocate a fresh output buffer for every event, and a separate
	// pool would add a second Get/Put per event. A wrapper is handed back once
	// its event has been sent (or dropped), since gRPC copies the payload into
	// its own frame synchronously during Send. Reuse is safe: gRPC's codec calls
	// proto.Size before each marshal (refreshing any cached size), the events
	// are never unmarshaled on this side, and Send is synchronous. Only
	// EventTypeGadgetPayload events are recycled.
	eventPool := sync.Pool{New: func() any { return &api.GadgetEvent{} }}

	// Create a new logger that logs to gRPC and falls back to the standard logger when it failed to send the message
	logger := logger.NewFromGenericLogger(&Logger{
		send: func(event *api.GadgetEvent) error {
			select {
			case outputBuffer <- event:
			default:
				return fmt.Errorf("output buffer full")
			}
			return nil
		},
		level:          logger.Level(ociRequest.LogLevel),
		fallbackLogger: s.logger,
	})

	for k, v := range ociRequest.ParamValues {
		logger.Debugf("param %s: %s", k, v)
	}

	done := make(chan bool)
	defer func() {
		close(done)
	}()

	// Build a simple operator that subscribes to all events and forwards them
	svc := simple.New("svc",
		simple.WithPriority(50000),
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			log := gadgetCtx.Logger()

			go func() {
				// Receive control messages
				for {
					msg, err := runGadget.Recv()
					if err != nil {
						s.logger.Warnf("error on connection: %v", err)
						gadgetCtx.Cancel()
						return
					}
					switch msg.Event.(type) {
					case *api.GadgetControlRequest_StopRequest:
						log.Debugf("received stop request")
						gadgetCtx.Cancel()
						return
					default:
						s.logger.Warn("received unexpected request")
					}
				}
			}()

			go func() {
				// Message pump to handle slow readers
				for {
					select {
					case ev := <-outputBuffer:
						runGadget.Send(ev)
						if ev.Type == api.EventTypeGadgetPayload {
							// Payload buffer stays attached; next marshal reuses
							// it via MarshalAppend(event.Payload[:0]).
							eventPool.Put(ev)
						}
					case <-done:
						return
					}
				}
			}()

			seq := uint32(0)
			var seqLock sync.Mutex

			gi, err := gadgetCtx.SerializeGadgetInfo(false)
			if err != nil {
				return fmt.Errorf("serializing gadget info: %w", err)
			}

			// datasource mapping; we're sending an array of available DataSources including a
			// DataSourceID; this ID will be used when sending actual data and needs to be remapped
			// to the actual DataSource on the client later on
			dsLookup := make(map[string]uint32)
			for i, ds := range gi.DataSources {
				ds.Id = uint32(i)
				dsLookup[ds.Name] = ds.Id
			}

			// todo: skip DataSources we're not interested in

			for _, ds := range gadgetCtx.GetDataSources() {
				dsID := dsLookup[ds.Name()]
				ds.SubscribePacket(func(ds datasource.DataSource, packet datasource.Packet) error {
					event, _ := eventPool.Get().(*api.GadgetEvent)
					// Marshal into the event's own attached buffer; reused across
					// recycles, so this is zero-alloc in steady state.
					d, _ := proto.MarshalOptions{}.MarshalAppend(event.Payload[:0], packet.Raw())
					event.Type = api.EventTypeGadgetPayload
					event.Payload = d
					event.DataSourceID = dsID

					seqLock.Lock()
					seq++
					event.Seq = seq

					// Try to send event; if outputBuffer is full, it will be dropped by taking
					// the default path.
					select {
					case outputBuffer <- event:
					default:
						// Dropped: recycle the wrapper right away. Payload buffer
						// stays attached for the next marshal.
						eventPool.Put(event)
					}
					seqLock.Unlock()
					return nil
				}, 1000000) // TODO: static int?
			}

			// Send gadget information
			d, _ := proto.Marshal(gi)
			err = runGadget.Send(&api.GadgetEvent{
				Type:    api.EventTypeGadgetInfo,
				Payload: d,
			})
			if err != nil {
				s.logger.Warnf("sending gadgetInfo: %v", err)
			}
			s.logger.Debugf("sent gadget info")

			return nil
		}),
	)

	ops := make([]operators.DataOperator, 0)
	for op := range s.operators {
		ops = append(ops, op)
	}
	ops = append(ops, svc)

	gadgetCtx := gadgetcontext.New(
		runGadget.Context(),
		ociRequest.ImageName,
		gadgetcontext.WithLogger(logger),
		gadgetcontext.WithDataOperators(ops...),
		gadgetcontext.WithTimeout(time.Duration(ociRequest.Timeout)),
		gadgetcontext.WithAsRemoteCall(true),
	)

	runtimeParams := s.runtime.ParamDescs().ToParams()
	runtimeParams.CopyFromMap(ociRequest.ParamValues, "runtime.")

	err = s.runtime.RunGadget(gadgetCtx, runtimeParams, ociRequest.ParamValues)
	if err != nil {
		return err
	}
	return nil
}
