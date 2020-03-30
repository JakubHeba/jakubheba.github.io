# Polymorphism

<p style="text-align: justify;">In this exercise, we will try to analyze and use polymorphism on three ready shellcodes hosted on shell-storm.com.</p>

<p style="text-align: justify;">Polymorphism consists in optimizing or changing the program code while keeping all its functionalities. This technique is very often used to deceive and bypass security systems such as antivirus programs.<p>

### Analysis and use of polymorphism, part I: ###

- [File Reader](File-Reader)
<p style="text-align: justify;">Using JMP-CALL-POP technique, <i>sys_open, sys_read(), sys_write()</i> and <i>sys_exit()</i> system calls to read any file on the filesystem</p>

### Part II: ###
- [Mkdir](Mkdir)
<p style="text-align: justify;">Using JMP-CALL-POP technique, <i>sys_mkdir()</i> and <i>sys_exit()</i> system calls to create a folder on the filesystem</p>

### Part III: ###
- [Modify Hosts File](Modify-Hosts) 
<p style="text-align: justify;">Using JMP-CALL-POP technique, <i>sys_read(), sys_write()</i> and <i>sys_exit()</i> system calls to update the content of "/etc/hosts"</p>
