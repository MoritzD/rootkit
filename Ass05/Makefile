module = hide_socket
obj-m += $(module).o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insert: all
	insmod $(module).ko udpPorts=55,702 tcpPorts=1,22,6011

remove:
	rmmod $(module)

user:
	$(CC) -o userland userland.c
