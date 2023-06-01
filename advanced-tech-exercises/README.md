# Advanced technologies exercises

We prepare 4 tasks to demostrate the use of some anti-reverse techniques.

For every program, you can use gdb to see its real control flow, and compare to the faulty control flow provided by 
Objdump or IDA pro.

For example, you can use `objdump linear_bypass`, obtaining results as below:
```
❯ objdump -M att -d linear_bypass_jmp

linear_bypass_jmp:     file format elf64-x86-64


Disassembly of section .text:

0000000000401000 <.text>:
  401000:       b8 04 00 00 00          mov    $0x4,%eax
  401005:       bb 01 00 00 00          mov    $0x1,%ebx
  40100a:       b9 27 10 40 00          mov    $0x401027,%ecx
  40100f:       ba 05 00 00 00          mov    $0x5,%edx
  401014:       cd 80                   int    $0x80
  401016:       c3                      retq   
  401017:       eb 01                   jmp    0x40101a
  401019:       e8 6a 2a e8 df          callq  0xffffffffe0283a88
  40101e:       ff                      (bad)  
  40101f:       ff                      (bad)  
  401020:       ff 31                   pushq  (%rcx)
  401022:       c0 ff c0                sar    $0xc0,%bh
  401025:       cd 80                   int    $0x80
  401027:       68 65 6c 6c 6f          pushq  $0x6f6c6c65
```

But if you use gdb to track the execution flow, you will find the real instruction sequence is like:
```
global _start
section .text
	do_write:
		mov eax, 4h
		mov ebx, 1h
		mov ecx, msg
		mov edx, 5h
		int 80h
		ret

	_start:
		jmp loc3
		
		db 0E8h
		
		loc3:
			push 2Ah
			call do_write

		xor eax, eax
		inc eax
		int 80h

msg	db "hello",0
```

## A brief describtion of the binaries
1. linear_bypass
A program defeat linear disassembly algorithm, such as objdump.

2. flow_bypass
A program defeat flow-oriented disassembly algorithm, such as objdump/IDA pro.

3. code_flattening
A program using code flattening to put more complexity on a function. 
You need to recover the logic of the function.

4. anti_decompilation
A complex task, involving multiple anti-compilation techniques such as pointer function calls, jmp invalid bytes, and string xor.
You can patch some bytes using ida, to recover the control flow. The method of patching can be found in Lab9 docs/warmup. 