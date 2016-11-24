obj-m := minifirewall.o
KERNEL_PATH := ~/Desktop/goldfish
NDK_PATH := ~/android-ndk-r13b/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin/
NDK_EXT := arm-linux-androideabi-

all:
	make ARCH=arm CROSS_COMPILE=$(NDK_PATH)/$(NDK_EXT) -C $(KERNEL_PATH) M=$(PWD) modules
ubuntu:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
	rm -rf *.c~
	rm -rf *.o
	rm -f modules.order
