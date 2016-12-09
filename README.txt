************************************************
*************	IMPORTANT	****************
************************************************


#To test this module on Ubuntu VM, we have provided the Makefile. To get the kernel module, you would require few things before compilation:
	-> 64bit Ubuntu VM
	
	To compile the program, run
	$make ubuntu
	
	This will generate the minifirewall.ko for ubuntu

#To test this module on Android, you will need the following things:
	-> 64bit Ubuntu VM (for compiling the module)
	-> Android Emulator running OS 5.1.1 (API 22), with modified goldfish kernel to support LKM
	-> Android NDK. Get it from = https://dl.google.com/android/repository/android-ndk-r13b-linux-x86_64.zip
	-> Android kernel source code (with LKM enabled)

	To compile the program, modify the Makefile with appropriate paths and then run
	$make

	This will generate the minifirewall.ko for android
	
	Push it to android and load the module. Done!

	
	