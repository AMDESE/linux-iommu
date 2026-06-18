# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_SDXI) += sdxi.o

sdxi-objs += \
	admin.o       \
	completion.o  \
	context.o     \
	descriptor.o  \
	device.o      \
	dma.o         \
	error.o       \
	intr.o        \
	keys.o        \
	process.o     \
	ring.o        \
	sysfs.o       \
	trace.o

sdxi-$(CONFIG_PCI_MSI) += pci.o

obj-$(CONFIG_SDXI_KUNIT_TEST) += \
	descriptor_kunit.o    \
	ring_kunit.o
