# SPDX-License-Identifier: GPL-2.0
#
# Deliberately not wired into the selftests build. The harness drives a real
# AMD vIOMMU through a VF bound to vfio-pci, so it cannot run on an arbitrary
# machine and has no business failing someone's kselftest run.
#
# It builds against this tree's own uapi headers rather than the system ones,
# because it tracks IOMMU_VIOMMU_MIG_STATE as that interface changes. Run
# "make headers_install" in the kernel root first.

KDIR ?= ../../..

CFLAGS += -Wall -O2 -I$(KDIR)/usr/include

all: mig-harness

mig-harness: mig-harness.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	$(RM) mig-harness

.PHONY: all clean
