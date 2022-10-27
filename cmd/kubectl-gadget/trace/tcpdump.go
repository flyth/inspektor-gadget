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

package trace

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpdump/types"
	"github.com/spf13/cobra"
)

type Decoder string

type TCPDumpParser struct {
	commonutils.BaseParser[types.Event]
	pcapngWriter   *pcapgo.NgWriter
	decoder        Decoder
	snapLen        int
	filter         string
	interfaces     map[string]int
	interfacesLock sync.RWMutex
}

const (
	DecoderWireshark = "wireshark"
	DecoderTCPDump   = "tcpdump"
	DecoderExternal  = "external"
	DecoderInternal  = "internal"
	DecoderFile      = "file"
)

var decoderCmd *exec.Cmd

func newTCPDumpCmd() *cobra.Command {
	commonFlags := &utils.CommonFlags{
		OutputConfig: commonutils.OutputConfig{
			OutputMode:    commonutils.OutputModeCustom,
			CustomColumns: []string{},
		},
	}

	var decoderParam string
	var decoderArgsParam string
	var decoderBinaryParam string
	var snapLen int
	var filenameParam string

	cmd := &cobra.Command{
		Use:   "tcpdump",
		Short: "Trace packets",
		RunE: func(cmd *cobra.Command, args []string) error {
			decoderArgs := []string{}
			var decoder Decoder
			var decoderBinary string
			var ngw *pcapgo.NgWriter

			// Writer, used for external output (pcapng)
			var out io.Writer

			switch Decoder(decoderParam) {
			case DecoderWireshark:
				decoder = DecoderExternal
				decoderArgs = []string{"-k", "-i", "-"}
				decoderBinary = "wireshark"
			case DecoderTCPDump:
				decoder = DecoderExternal
				decoderArgs = []string{"-r", "-"}
				decoderBinary = "tcpdump"
			case DecoderInternal:
				decoder = DecoderInternal
			case DecoderFile:
				decoder = DecoderFile
			default:
				return errors.New("unknown decoder")
			}

			if decoder == DecoderFile {
				if filenameParam == "" {
					return fmt.Errorf("no filename specified")
				}
				f, err := os.Create(filenameParam)
				if err != nil {
					return fmt.Errorf("creating file: %w", err)
				}
				out = f
			}

			if decoder == DecoderExternal {
				r, w, err := os.Pipe()
				if err != nil {
					return fmt.Errorf("could not create pipe: %w", err)
				}

				if decoderArgsParam != "" {
					decoderArgs = append(decoderArgs, strings.Split(decoderArgsParam, " ")...)
				}
				if decoderBinaryParam != "" {
					decoderBinary = decoderBinaryParam
				}

				decoderCmd = exec.Command(decoderBinary, decoderArgs...)
				decoderCmd.Stdout = os.Stdout
				decoderCmd.Stderr = os.Stderr
				decoderCmd.Stdin = r
				err = decoderCmd.Start()
				if err != nil {
					return fmt.Errorf("could not start tcpdump: %w", err)
				}

				out = w
			}

			if out != nil {
				var err error
				dummyInterface := pcapgo.DefaultNgInterface
				dummyInterface.LinkType = layers.LinkTypeEthernet
				dummyInterface.SnapLength = uint32(snapLen)
				ngw, err = pcapgo.NewNgWriterInterface(out, dummyInterface, pcapgo.NgWriterOptions{SectionInfo: pcapgo.NgSectionInfo{
					Hardware:    runtime.GOARCH,
					OS:          runtime.GOOS,
					Application: "InspektorGadget",
					Comment:     "using gopacket",
				}})
				if err != nil {
					return fmt.Errorf("instantiating NgWriter: %w", err)
				}
				ngw.Flush()
			}

			filter := strings.Join(args, " ")

			tcpdumpGadget := &TraceGadget[types.Event]{
				name:        "tcpdump",
				commonFlags: commonFlags,
				parser:      NewTCPDump(&commonFlags.OutputConfig, filter, snapLen, decoder, ngw),
				params: map[string]string{
					types.FilterStringParam: filter,
					types.SnapLenParam:      strconv.Itoa(snapLen),
				},
			}

			return tcpdumpGadget.Run()
		},
	}

	utils.AddCommonFlags(cmd, commonFlags)
	cmd.Flags().StringVar(&decoderParam, "decoder", "internal", "name of the decoder to use (either tcpdump, wireshark, internal or file)")
	cmd.Flags().StringVar(&decoderArgsParam, "decoder-args", "", "arguments to forward to decoder")
	cmd.Flags().StringVar(&decoderBinaryParam, "decoder-binary", "", "path to decoder binary (defaults to 'wireshark' or 'tcpdump' depending on decoder)")
	cmd.Flags().StringVar(&filenameParam, "out-file", "", "output file name")
	cmd.Flags().IntVar(&snapLen, "snaplen", 68, "number of bytes to capture")
	return cmd
}

func NewTCPDump(outputConfig *commonutils.OutputConfig, filter string, snapLen int, decoder Decoder, pcapngWriter *pcapgo.NgWriter) commontrace.TraceParser[types.Event] {
	columnsWidth := map[string]int{}
	outputConfig.OutputMode = commonutils.OutputModeCustom
	return &TCPDumpParser{
		BaseParser:   commonutils.NewBaseWidthParser[types.Event](columnsWidth, outputConfig),
		filter:       filter,
		snapLen:      snapLen,
		decoder:      decoder,
		pcapngWriter: pcapngWriter,
		interfaces:   make(map[string]int),
	}
}

func (p *TCPDumpParser) getPodInterface(event *types.Event) int {
	p.interfacesLock.RLock()
	if id, ok := p.interfaces[event.Container]; ok {
		p.interfacesLock.RUnlock()
		return id
	}
	p.interfacesLock.RUnlock()
	// Define new interface
	p.interfacesLock.Lock()
	id, err := p.pcapngWriter.AddInterface(pcapgo.NgInterface{
		Name:        event.Container,
		Comment:     "",
		Description: fmt.Sprintf("Node: %s, Namespace: %s, Pod: %s", event.Node, event.Namespace, event.Pod),
		Filter:      p.filter,
		OS:          "",
		LinkType:    layers.LinkTypeEthernet,
		SnapLength:  uint32(p.snapLen),
		Statistics:  pcapgo.NgInterfaceStatistics{},
	})
	if err != nil {
		panic(fmt.Errorf("registering interface: %w", err))
	}
	p.interfaces[event.Container] = id
	p.interfacesLock.Unlock()
	return id
}

func (p *TCPDumpParser) TransformIntoColumns(event *types.Event) string {
	// This is a hack for now - we use "custom" output mode and have this method called to
	// forward packets to tcpdump / decode ourselves
	if p.decoder == DecoderInternal {
		packet := gopacket.NewPacket(event.Payload, layers.LayerTypeEthernet, gopacket.NoCopy)
		fmt.Println(packet.String())
	} else {
		log.Printf("%d", len(event.Payload))
		id := p.getPodInterface(event)
		err := p.pcapngWriter.WritePacket(gopacket.CaptureInfo{
			Timestamp:      time.Now(), // from node
			CaptureLength:  len(event.Payload),
			Length:         len(event.Payload),
			InterfaceIndex: id,
		}, event.Payload)
		if err != nil {
			log.Printf("error: %v", err)
		}
		p.pcapngWriter.Flush()
	}
	return ""
}
