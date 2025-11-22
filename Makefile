KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(PWD)/pt modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/pt clean
