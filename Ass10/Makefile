module = hypercall
obj-m += $(module).o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insert:
	insmod $(module).ko

remove:
	rmmod $(module)

