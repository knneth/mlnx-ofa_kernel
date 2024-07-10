ifneq ($(filter m,$(CONFIG_INFINIBAND_HNS) $(CONFIG_INFINIBAND_HISILICON_HNS)),)
obj-m += hns-roce.o
endif

hns-roce-y  := main.o

ifdef CONFIG_INFINIBAND_HNS_HIP06
obj-$(CONFIG_INFINIBAND_HNS) += hns-roce-hw-v1.o
obj-$(CONFIG_INFINIBAND_HNS_HIP06) += hns-roce-hw-v1.o
endif
hns-roce-hw-v1-objs := hns_roce_hw_v1.o
ifdef CONFIG_INFINIBAND_HNS_HIP08
obj-$(CONFIG_INFINIBAND_HNS) += hns-roce-hw-v2.o
obj-$(CONFIG_INFINIBAND_HNS_HIP08) += hns-roce-hw-v2.o
endif
hns-roce-hw-v2-objs := hns_roce_hw_v2.o

