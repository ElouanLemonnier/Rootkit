obj-m += rootkit.o
#CC = gcc -wall
#KDIR := /lib/modules/$(shell uname -r)/build
#PWD := $(shell pwd)
my_rootkit-objs := rootkit.o 

all:
	make -C ../linux M=$(PWD) modules

clean:
	make -C ../linux M=$(PWD) clean
