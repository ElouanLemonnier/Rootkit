# Rootkit LKM

This is a rootkit made for a school project to learn about the Linux Kernel functioning.

This rootkit was implemented as a Linux Kernel Module and was tested on a Alpine Linux 3.16 Docker image.

To use the Makefile provided you will need to have a folder containing the linux kernel source.
## Functionalities

- Root access
- Hiding itself in the lsmod output
- Hiding files and directories
- Hiding processes
- Make itself persistant (Automatic reinsertion on target reboot)

## How it works 

I decided to create a rootkit that bases itself on syscall hooking to execute its malicious features.

### Step 1 : Get the syscall table :

First thing was to retrieve the address of the kallsyms_lookup_name function by creating a kprobe. 

After getting this address we can use this function to search for the sys_call_table symbol address that is stored in memory. 

The syscall table gave me the ability to locate every syscall in memory by giving the id of that syscall. (Ex : \__\_NR_kill for the kill syscall)

### Step 2 : Unprotect memory

Before hooking the syscalls we need to make sure the target won't detect it by unprotecting the memory.

I created 3 functions : protect_memory(), unprotectmemory() and write_cr0_forced()

The first 2 will call write_cr0_forced() which will flip the 16th bit of the cr0 register. Flipping it will allow us to write memory without getting an error. 

### Step 3 : Hooking syscalls

Now that the memory is unprotected we can start hooking syscalls by using hook() and store().

The store function will get the original syscall addresses and store them into variables to ensure we can use them if something goes wrong.

The hook function will replace the original address by the address of my own syscall function.

Now every time this function is called our function will execute instead of the original syscall.

If we decide to remove our rootkit a clean function will be called automaticaly to put the original syscalls in their place.

### Step 4 : Creating our own kill syscall

I decided to use the kill syscall to call my malicious functionalities.

The way the kill syscall works is by giving it a signal (An int that goes from 0 to 31) and a PID.

However if I control this syscall I can create signals of my own. 

So I created these signals : 

1. SIGHIDEF (60) : Will start hiding folders and files
2. SIGPER (61) : Will make the rootkit auto load on reboot
3. SIGPID (62) : Will hide and process in ps command output
4. SIGINVIS (63) : Will hide the rootkit in the lsmod command output
5. SIGSUPER (64) : Will make the user that runs it become root

Each time the kill syscall is called our function will check if the signal given to it is equal to one of these values. Else it will return the original kill syscall.

### Step 5 : Hiding files and processes

To hide files and folder we need to erase them from the output of the `ls` command.

To do this we need to hook the syscall called by `ls` : **getdents64**

First we need to recode getdents so we can return the good output if we don't find a file to be hidden.

The way we can set a file to be hidden is by giving him a prefix. In my case this prefix is "sneaky". (Ex : "frog.txt" would become "sneaky_frog.txt")

When running our getdents64 we will check each file for this prefix and removing the current directory from the final output. 

To do this we simply remove from the return variable and then use memmove to shift the next directory's address on our hidden file address. Else it would cause the ls command to crash.

Using SIGHIDEF will just set the hidef variable to 0 or 1. Each time getdents64 is called we check if this variable is set to 0, if it is we return the original getdents64.

Since the `ps` command also use getdents64 we can hide processes in the same way. 

But this time instead of checking for a prefix our getdents64 will simply use the PID that is given to the kill syscall to identify the process to hide.

### Step 6 : Hiding itself

Each time SIGINVIS is called we check if the hidden variable is set to either 0 or 1. 

If it is set to 0 we will call the hide() function that will store the address of the previous module in the module linked list and the use list_del to remove our module from this list. Then hidden will be set to 1. 

If it is set to 1 we will call the show function which will use the previous module address in list_add to add our rootkit at the same place it was before in the modules linked list. Then hidden will be set to 0.

When the module is removed from the linked list, it won't be outputed by the `lsmod` command.

### Step 7 : Becoming Root

To become root it's quite simple. 

I created a set_root function that will use the prepare_creds function fetch all the UIDS and GIDS of the current user and put them in a struct. 

Then we just use this struct to set them all to 0. 

We use the commit_creds function to commit or changes and, voilà !

### Step 8 : Becoming persistent

This is the part that easily got me the most trouble to get done.

To do it I decided to create a bash file named sneaky_per.start in the /etc/local.d/ directory because each executable file named that end with ".start" in this directory will be executed on startup.

This file will contain `insmod /root/my_modules/rootkit.ko\n` to insert the rootkit LKM. 

However, since we are coding a Kernel Module we can't use all the user land functions. Such as fwrite(). So we have to code it ourselves. 

Hopefully this [Article](https://www.linuxjournal.com/article/8110) existed. And after some adaptations to fit the current C standards and Linux kernel version I had a function that allowed me to create a file and write in it from the Kernel Land to the User Land by using filp_open() and kernel_write(). 

However, this file needs to have the execution rights. And we can't just call chmod on it. So I created a function that would use kallsyms_lookup_name to get the address of vfs_fchmod which is a function in the  linux kernel that can perform a chmod given a filepath and a mode.

So each time SIGPER is called we call write_file() to create a file in /etc/local.d/ named sneaky_per.start containing an insmod command. And then we call chmod() to give it execution rights. 

## Sources :

[Rootkit LKM Tutorial Part 1](https://www.youtube.com/watch?v=hsk450he7nI)
[Rootkit LKM Tutorial Part 2](https://www.youtube.com/watch?v=jw9kuN1lhiw)
[Functionalities Tutorial](https://xcellerator.github.io/tags/rootkit/)
[The linux source code](https://elixir.bootlin.com/linux/v6.7.6/source)
[Things You Never Should Do in the Kernel](https://www.linuxjournal.com/article/8110)
