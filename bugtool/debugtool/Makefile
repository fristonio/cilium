# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

CURR_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")
CGO_ENABLED := 1

include $(CURR_DIR)/../../Makefile.defs

TARGET := cilium-debugtool

.PHONY: all $(TARGET) clean install

all: $(TARGET)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	-$(QUIET)rm -f $(TARGET)
	$(QUIET)rm -rf debug-state
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(QUIET)$(INSTALL) -m 0755 $(TARGET) $(DESTDIR)$(BINDIR)

setup:
	$(QUIET)curl https://install.duckdb.org | sh

dbui:
	$(QUIET)duckdb debug-state/cilium-debug-state.db -ui

install-binary: install
