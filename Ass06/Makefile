module = hide_packet
obj-m += $(module).o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insert: all
	insmod $(module).ko

remove:
	rmmod $(module)

user:
	$(CC) -o userland userland.c
