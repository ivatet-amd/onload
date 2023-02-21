# SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2022 Xilinx, Inc.

# Override this to run only the subset of the tests beginning with the filter
# e.g. tests in a single directory: UNIT_TEST_FILTER=lib/transport/ip/
#      single test: UNIT_TEST_FILTER=lib/transport/ip/tcp_rx
UNIT_TEST_FILTER ?=

# Override this to run tests under a wrapper (e.g. gdb, valgrind)
UNIT_TEST_WRAPPER ?=

# All the tests that can be run. Can be filtered using UNIT_TEST_FILTER.
# In principle, this could be autogenerated by searching the source directory.
ALL_UNIT_TESTS := \
  header/ci/internal/ip_timestamp \
  lib/transport/ip/tcp_rx \
  lib/transport/ip/tcp_tx \

# The tests to be run, and their corresponding files
TESTS := $(filter $(UNIT_TEST_FILTER)%, $(ALL_UNIT_TESTS))
TARGETS := $(TESTS:%=$(AppPattern))
OBJECTS := $(TESTS:%=%.o)
PASSED := $(TESTS:%=%.passed)

# Library objects names are mangled with a prefix. Deal with that madness here.
LIB_PREFIXES := lib/transport/common/ci_tp_common_ lib/transport/ip/ci_ip_

lib_prefix = $(notdir $(filter $(dir $(1))%,$(LIB_PREFIXES)))
lib_object = ../../$(dir $(1))$(call lib_prefix,$(1))$(notdir $(1)).o

# TODO can we rely on a sufficiently up-to-date version of make?
.SECONDEXPANSION:

all: $(PASSED)

# Sentinel files indicate that a test has passed. The test only needs to be
# run again if the sentinel is out of date.
$(PASSED): %.passed: %
	@echo UNIT TEST $<
	@$(UNIT_TEST_WRAPPER) $< && touch $@

# Object files require their corresponding directory. Depend on a sentinel file
# rather than the directory, whose timestamp may change when files are modified.
$(OBJECTS): % : $$(@D)/.unit_test_dir
%/.unit_test_dir:
	@mkdir -p $(@D)
	@touch $@

# Test programs are linked with the object under test, and stub dependencies.
#
# CAVEAT: the fragmented build system means that the object under test will NOT
# be rebuilt if out of date. A top-level build is needed to make sure it's up
# to date before building the tests. This sadly means we can't reliably run an
# invididual test without waiting for several seconds of flappery first.
$(TARGETS): MMAKE_DIR_LINKFLAGS += -Wl,--unresolved-symbols=ignore-all -no-pie
$(filter lib/%, $(TARGETS)): $$(call lib_object,$$@)
$(TARGETS): %: %.o stubs.o
	$(MMakeLinkCApp)

# The build system relies on a convoluted web of makefiles in subdirectories
# of both source and build trees to generate the dependencies. Lets do it the
# easy way instead. TODO remove this once the build system is more sensible.
$(OBJECTS): MMAKE_DIR_CFLAGS += -MMD -MP
-include $(subst .o,.d,$(OBJECTS))
