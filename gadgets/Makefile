SHELL := /bin/bash

GADGET_TAG ?= $(shell ../tools/image-tag branch)
GADGET_REPOSITORY ?= ghcr.io/inspektor-gadget/gadget
BUILDER_IMAGE ?= ghcr.io/inspektor-gadget/ebpf-builder:latest
IG ?= ig
GADGETS = \
	trace_dns \
	trace_exec \
	trace_mount \
	trace_oomkill \
	trace_open \
	trace_signal \
	trace_sni \
	trace_tcp \
	trace_tcpconnect \
	trace_tcpdrop \
	trace_tcpretrans \
	snapshot_process \
	snapshot_socket \
	ci/sched_cls_drop \
	#

.PHONY: all
all: build

build: $(GADGETS)

.PHONY: $(GADGETS)
$(GADGETS):
	@echo "Building $@"
	@sudo -E IG_EXPERIMENTAL=true $(IG) image build --builder-image $(BUILDER_IMAGE) \
		-t $(GADGET_REPOSITORY)/$@:$(GADGET_TAG) $@

.PHONY:
push: build
	@echo "Pushing all gadgets"
	for GADGET in $(GADGETS); do \
		sudo -E IG_EXPERIMENTAL=true $(IG) image push $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG) || exit 1 ; \
	done

.PHONY:
clean:
	for GADGET in $(GADGETS); do \
		sudo -E IG_EXPERIMENTAL=true $(IG) image remove $(GADGET_REPOSITORY)/$$GADGET:$(GADGET_TAG); \
	done
