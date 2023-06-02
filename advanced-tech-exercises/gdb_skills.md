# How to use gdb for debugging
In this document we show you how to use gdb to debug a program, taking `linear_bypass` as an example.

## What is GDB?
The GNU debugger, terminal-based. GDB can be used as a powerful tool to debug ELF.

1. Debug an executable:
    ```
    gdb executable
    ```
2. Attach to a process:
    ```
    gdb -p pid
    ```

TLDR information: http://www.cheat-sheets.org/project/tldr/command/gdb/.

Detailed information:  https://www.gnu.org/software/gdb.

## Running example
Firstly, use gdb to open `linear_bypass`:
```
gdb -q linear_bypass
```
Then you can interact with gdb. 
```
❯ gdb -q linear_bypass
Reading symbols from linear_bypass...
(No debugging symbols found in linear_bypass)
(gdb) 
```
However, the program has not been run. We can use `starti` to start it.
```
(gdb) starti
Starting program: /mnt/c/master/pore/repos/demo-tasks/advanced-tech-exercises/linear_bypass 

Program stopped.
0x0000000000401017 in ?? ()
(gdb) 
```
The program stops at 0x401017, this is the entry point of the program. We can verify this point using readelf -h:
```
❯ readelf -h linear_bypass
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x401017
  Start of program headers:          64 (bytes into file)
  Start of section headers:          4160 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         2
  Size of section headers:           64 (bytes)
  Number of section headers:         3
  Section header string table index: 2
```
Back to the debugging session, we can use `x/16i 0x401017` to see the 16 next instructions.
```
(gdb) x/16i 0x401017
=> 0x401017:    jmp    0x40101a
   0x401019:    callq  0xffffffffe0283a88
   0x40101e:    (bad)  
   0x40101f:    (bad)  
   0x401020:    pushq  (%rcx)
   0x401022:    sar    $0xc0,%bh
   0x401025:    int    $0x80
   0x401027:    pushq  $0x6f6c6c65
   0x40102c:    add    %al,(%rax)
   0x40102e:    jae,pn 0x401099
   0x401031:    jae    0x4010a7
   0x401033:    jb     0x4010a9
   0x401035:    (bad)  
   0x401036:    (bad)  
   0x401037:    add    %ch,(%rsi)
   0x401039:    je     0x4010a0
(gdb)
``` 
We can see, the disassemble fails at 0x40101e and 0x40101f. But if we using si to trace the execution, we will find that we directly reach 0x40101a by seeing the value of $eip.
```
(gdb) info registers eip
eip            0x40101a            0x40101a
(gdb) x/16i 0x40101a
=> 0x40101a:    pushq  $0x2a
   0x40101c:    callq  0x401000
   0x401021:    xor    %eax,%eax
   0x401023:    inc    %eax
   0x401025:    int    $0x80
   0x401027:    pushq  $0x6f6c6c65
   0x40102c:    add    %al,(%rax)
   0x40102e:    jae,pn 0x401099
   0x401031:    jae    0x4010a7
   0x401033:    jb     0x4010a9
   0x401035:    (bad)  
   0x401036:    (bad)  
   0x401037:    add    %ch,(%rsi)
   0x401039:    je     0x4010a0
   0x40103b:    js     0x4010b1
   0x40103d:    add    %al,(%rax)
(gdb)
```
Continue to execute `si`, we then enter 0x401000
```
(gdb) x/16i 0x0000000000401000
=> 0x401000:    mov    $0x4,%eax
   0x401005:    mov    $0x1,%ebx
   0x40100a:    mov    $0x401027,%ecx
   0x40100f:    mov    $0x5,%edx
   0x401014:    int    $0x80
   0x401016:    retq   
   0x401017:    jmp    0x40101a
   0x401019:    callq  0xffffffffe0283a88
   0x40101e:    (bad)  
   0x40101f:    (bad)  
   0x401020:    pushq  (%rcx)
   0x401022:    sar    $0xc0,%bh
   0x401025:    int    $0x80
   0x401027:    pushq  $0x6f6c6c65
   0x40102c:    add    %al,(%rax)
   0x40102e:    jae,pn 0x401099
(gdb)
```
There is a `int 0x80` instruction, which is a `system call` in linux. We can reach 0x40100f to see the arguments of the syscall.
```
(gdb) tbreak *0x401014
Temporary breakpoint 1 at 0x401014
(gdb) c
Continuing.

Temporary breakpoint 1, 0x0000000000401014 in ?? ()
(gdb) i r eax ebx ecx edx
eax            0x4                 4
ebx            0x1                 1
ecx            0x401027            4198439
edx            0x5                 5
(gdb) x/s 0x401027
0x401027:       "hello"
```
So, we find that $eax = 4, which means `write` syscall will be invoked. According to other registers, the syscall will be:
```
write(1, "hello", 5)
```

You can use the `si` to see the whole execution flow.


## Other tips
Using some gdb plugins (e.g., GEF, pwndbg) will be very helpful.
