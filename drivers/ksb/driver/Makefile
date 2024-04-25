CFLAGS_MODULE += -DCONFIG_WITH_VF_PROBE

TARGET = ksb_pci_drv

obj-$(CONFIG_KSB) += $(TARGET).o
ksb_pci_drv-objs := ksb_drv_main.o ksb_cdx_dev.o ksb_cdm_exerciser.o \
                    ksb_csi_exerciser.o ksb_mcdi.o ksb_mcdi_cmd.o \
					ksb_dpu_exerciser.o
