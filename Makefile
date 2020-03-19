PWD := $(shell pwd)

ccflags-y += -I$(src)/include/ -msse3 -msse4.1 -mavx2 -mpreferred-stack-boundary=4

RStest-objs := main.o cauchy_rs.o aont.o read_file.o
obj-m += RStest.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

test:
	sudo insmod RStest.ko
	sudo rmmod RStest.ko

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
