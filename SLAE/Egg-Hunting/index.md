# Egg Hunting #

Definition. Following the [fantastic document](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) created by Skape:

*`It’s primarily useful for exploitation. Some exploit vectors only allowthe attacker a very small amount of data to use when accomplishing their bufferoverflow. For instance, the Internet Explorer object type vulnerability andthe Subversion date parsing vulnerability are both examples of overflows thatallow for a limited amount of data to be written and used as a payload at adeterministic location. However, both exploits allow for the attacker to placea large payload somewhere else in the address space of the process, thoughthe location that it is stored at is indeterminate.  In the case of the objecttype vulnerability, an attacker can place their egg somewhere else in the HTMLfile, which in the end is translated into a heap allocated buffer that stores thecontents of the page being processed.`*

In simple words, the Egg Hunting technique allows us to create a relatively short shellcode (~ 30), whose task is to search the memory (stack, heap, ...) in search of the original, long shellcode, which in normal conditions could not be used due to space restriction.

To this end, so-called tags are used, which is a string that will "point" to the beginning of the actual shellcode that immediately follows them.

Due to the speed of today's processors, the memory search process is rapid and almost imperceptible during exploitation.

In this article, I will try to describe the process of creating three different Egg Hunters listed in the Skapes document, namely:
- access #1
- access #2
- sigaction

### Access #1 ###

