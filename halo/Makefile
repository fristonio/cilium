# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

.DEFAULT_GOAL := all

ROOT_DIR := $(shell dirname "$(realpath $(lastword $(MAKEFILE_LIST)))")

include ${ROOT_DIR}/../Makefile.defs

# Add the ability to override variables
# ROOT_DIR changes to repo root after including Makefile.defs
-include ${ROOT_DIR}/Makefile.override

TARGETS := halo

.PHONY: all $(TARGETS) clean install

all: $(TARGETS)

halo: GO_TAGS_FLAGS+=

$(TARGETS):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $(@)

$(TARGET):
	@$(ECHO_GO)
	$(QUIET)$(GO_BUILD) -o $@

clean:
	@$(ECHO_CLEAN)
	$(QUIET)rm -f $(TARGETS)
	$(QUIET)$(GO_CLEAN)

install:
	$(QUIET)$(INSTALL) -m 0755 -d $(DESTDIR)$(BINDIR)
	$(foreach target,$(TARGETS), $(QUIET)$(INSTALL) -m 0755 $(target) $(DESTDIR)$(BINDIR);)

