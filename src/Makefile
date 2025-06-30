obj-m += pcp.o
obj-m += memoryleakguard.o
obj-m += privacyguard.o

KVERSION := $(shell uname -r)
KDIR := /lib/modules/$(KVERSION)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f Module.symvers Module.markers modules.order

install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

uninstall:
	rm -f /lib/modules/$(KVERSION)/extra/pcp.ko
	rm -f /lib/modules/$(KVERSION)/extra/memoryleakguard.ko
	rm -f /lib/modules/$(KVERSION)/extra/privacyguard.ko
	depmod -a 