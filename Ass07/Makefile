module = hacked_read_cooler
module2 = portKnocking
obj-m += $(module).o
obj-m += $(module2).o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insert:
	insmod $(module).ko

remove:
	rmmod $(module)

insertknocking:
	insmod $(module2).ko

removeknocking:
	rmmod $(module2)
