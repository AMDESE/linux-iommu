# SPDX-License-Identifier: GPL-2.0
#
# Deliberately not wired into the selftests build. The harness drives a real
# SDXI VF bound to sdxi_vfio_pci, so it cannot run on an arbitrary machine.
#
# Builds against this tree's uapi headers. Run "make headers_install" in the
# kernel root first if usr/include/linux/vfio.h is stale.

KDIR ?= ../../..

CFLAGS += -Wall -O2 -I$(KDIR)/usr/include

all: sdxi-mig-harness

sdxi-mig-harness: sdxi-mig-harness.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(RM) sdxi-mig-harness

.PHONY: all clean
