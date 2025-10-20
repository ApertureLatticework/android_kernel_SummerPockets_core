ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-int-conversion
ccflags-y += -Wno-unused-result
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-builtin-macro-redefined -U__FILE__ -D__FILE__='""'
ccflags-y += -Wno-error

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

$(info -- KDIR: $(KDIR))
$(info -- MDIR: $(MDIR))

obj-y += adios/
obj-y += baseguard/
obj-y += rekernel/
obj-y += sched_ext/
obj-y += ssg/
obj-y += symbol_check/
obj-y += tcp/

obj-$(CONFIG_LZ4K_COMPRESS) += lz4k/
obj-$(CONFIG_LZ4K_DECOMPRESS) += lz4k/
obj-$(CONFIG_LZ4KD_COMPRESS) += lz4kd/
obj-$(CONFIG_LZ4KD_DECOMPRESS) += lz4kd/
obj-$(CONFIG_CRYPTO_LZ4K) += lz4k.o
obj-$(CONFIG_CRYPTO_LZ4KD) += lz4kd.o

summerpockets-objs := abi.o
obj-$(CONFIG_SUMMER_POCKETS) += SummerPockets.o

all:
	make -C $(KDIR) M=$(MDIR) modules
compdb:
	python3 $(MDIR)/generate_compdb.py -O $(KDIR) $(MDIR)
clean:
	make -C $(KDIR) M=$(MDIR) clean
