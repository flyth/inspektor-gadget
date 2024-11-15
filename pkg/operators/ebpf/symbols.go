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

package ebpfoperator

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
)

var errNoSymbols = errors.New("no symbols found")

type symbolKey struct {
	address uint64
	ino     uint64
}

type symbolValue struct {
	time       int64
	symbolName string
}

type pidValue struct {
	time int64
	ino  uint64
}

func (i *ebpfInstance) getSymbols(name string, pid uint32, addresses []uint64) ([]string, error) {
	res := make([]string, len(addresses))
	invalids := make([]bool, len(addresses))
	foundInvalids := 0
	i.symbolCacheLock.RLock()
	pidInfo, ok := i.pidCache[pid]
	if ok && pidInfo.ino == 0 {
		i.symbolCacheLock.RUnlock()
		return nil, errNoSymbols
	}
	for idx, addr := range addresses {
		v, ok := i.symbolCache[symbolKey{
			address: addr,
			ino:     pidInfo.ino,
		}]
		if !ok {
			invalids[idx] = true
			foundInvalids++
			continue
		}
		res[idx] = v.symbolName
	}
	i.symbolCacheLock.RUnlock()
	if foundInvalids == 0 {
		log.Printf("0 invs")
		return res, nil
	}

	ts := time.Now().Unix()
	log.Printf("getting %d more symbols from %q", foundInvalids, name)
	path := fmt.Sprintf("/proc/%d/exe", pid)
	file, err := os.Open(path)
	if err != nil {
		i.symbolCacheLock.Lock()
		i.pidCache[pid] = pidValue{
			time: ts,
			ino:  0,
		}
		i.symbolCacheLock.Unlock()
		return nil, fmt.Errorf("opening process executable: %w", err)
	}
	defer file.Close()
	fs, err := file.Stat()
	if err != nil {
		i.symbolCacheLock.Lock()
		i.pidCache[pid] = pidValue{
			time: ts,
			ino:  0,
		}
		i.symbolCacheLock.Unlock()
		return nil, fmt.Errorf("stat process executable: %w", err)
	}
	stat, ok := fs.Sys().(*syscall.Stat_t)
	if !ok {
		i.symbolCacheLock.Lock()
		i.pidCache[pid] = pidValue{
			time: ts,
			ino:  0,
		}
		i.symbolCacheLock.Unlock()
		return nil, fmt.Errorf("getting syscall.Stat_t failed")
	}
	ino := stat.Ino

	elfFile, err := elf.NewFile(file)
	if err != nil {
		i.symbolCacheLock.Lock()
		i.pidCache[pid] = pidValue{
			time: ts,
			ino:  0,
		}
		i.symbolCacheLock.Unlock()
		return nil, fmt.Errorf("parsing ELF file: %w", err)
	}

	symtab, err := elfFile.Symbols()
	if err != nil {
		i.symbolCacheLock.Lock()
		i.pidCache[pid] = pidValue{
			time: ts,
			ino:  0,
		}
		i.symbolCacheLock.Unlock()
		return nil, fmt.Errorf("reading symbol table: %w", err)
	}

	i.symbolCacheLock.Lock()
	for idx, addr := range addresses {
		if !invalids[idx] {
			continue
		}
		found := false
		for _, sym := range symtab {
			if addr <= uint64(sym.Value) || addr > uint64(sym.Value)+uint64(sym.Size) {
				continue
			}
			found = true
			res[idx] = sym.Name
			i.symbolCache[symbolKey{
				address: addr,
				ino:     ino,
			}] = symbolValue{
				time:       ts,
				symbolName: sym.Name,
			}
			break
		}
		if !found {
			i.symbolCache[symbolKey{
				address: addr,
				ino:     ino,
			}] = symbolValue{
				time:       ts,
				symbolName: "-",
			}
		}
	}
	i.symbolCacheLock.Unlock()
	return res, nil
}
