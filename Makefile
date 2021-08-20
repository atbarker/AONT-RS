PWD := $(shell pwd)

ccflags-y += -I$(src)/include/ -msse3 -msse4.1 -mavx2 -mpreferred-stack-boundary=4

RStest-objs := main_kernel.o cauchy_rs.o aont.o speck.o sha3.o
obj-m += RStest.o

ALL: main

dependencies: 
	gcc -g -O2 -c aont.c -g
	gcc -g -O2 -c cauchy_rs.c -msse4.2 -g
	gcc -g -c speck.c
	gcc -g -c sha3.c

main: dependencies
	gcc -g -O2 -c main.c -g
	gcc -g -O2 -o main main.o aont.o cauchy_rs.o speck.o sha3.o -lkcapi -g

infer:
	make clean; infer-capture -- make; infer-analyze -- make

test: main
	./main

clean:
	rm *.o
	rm main


main_kernel:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

test_kernel:
	sudo insmod RStest.ko
	sudo rmmod RStest.ko

clean_kernel:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
