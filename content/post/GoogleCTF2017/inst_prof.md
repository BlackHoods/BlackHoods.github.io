---
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
date: 2017-08-30T18:56:18+02:00
description: GoogleCTF 2017 - Inst prof (Part 1)
tags:
- CTF
- GoogleCTF
- 2017
title: "GoogleCTF 2017 - Inst Prof (Part 1)"
summary: "Here there is an explanation and solution to one funny challenge published during the GoogleCTF 2017. As the explanation is a bit long I decided to split the post in two parts."
cardthumbimage: "/assets/TamuCTF2017/title.png"
---

![inst_prof Description](/assets/GoogleCTF2017/Inst Prof/1-inst_prof_description.png)

In this challenge we are given a [binary](/assets/GoogleCTF2017/Inst Prof/inst_prof) that is running remotely at [inst-prof.ctfcompetition.com:1337](inst-prof.ctfcompetition.com:1337).  
Probably the flag will be somewhere in the server.

 
We can start getting some basic information of the binary using the unix command `file`.
```bash
$ file inst_prof
inst_prof: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=61e50b540c3c8e7bcef3cb73f3ad2a10c2589089, not stripped
```
Interesting! It is an [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format), a binary for unix systems and it has been compiled for a 64 bits architecture. There is another interesting thing we will want to know about this architecture: [the calling convention](https://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions). More specifically: 

> The first six arguments [of a function] are passed in registers **RDI**, **RSI**, **RDX**, **RCX**, **R8**, and **R9**.  
> the return value is stored in **RAX** and **RDX**.

Knowing this, we can get an idea of which data is going to be sent/received to/from a certain function.  
All right! let's see what this binary does.

```bash
$ wget -q https://blackhoods.github.io/assets/GoogleCTF2017/Inst%20Prof/inst_prof
$ chmod +x inst_prof 
$ ./inst_prof 
initializing prof...ready
1234
Segmentation fault
```

If you execute it, you will realized that there is a delay of 5 seconds between **initializing prof...** and **ready** strings. We do not want to wait 5 seconds everytime we want to test something, so lets patch it. I also used **1234** as input but it resulted in a segmentation fault (we will realize the reason later).

```r2
$ r2 -Aw inst_prof
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[0x000008c9]>
```

> `-A` tells radare to analyze automatically the binary (so we wont need to use `aaa` inside radare).  
> `-w` tells radare to open the binary in writable-mode to let us edit it.
> Note that this time there is no `-d` (debug) flag. This is because, if especified, we will not be patching the binary itself but its memory process.
> So if you want to debug it, you need to open a new r2 session.

{{< highlight r2 "hl_lines=14 21 22 23 24 25 26 27" >}}
[0x000008c9]> afl
0x00000778    3 26           sym._init
0x000007b0    2 16   -> 32   sym.imp.write
0x000007c0    2 16   -> 48   sym.imp.mmap
0x000007d0    2 16   -> 48   sym.imp.alarm
0x000007e0    2 16   -> 48   sym.imp.read
0x000007f0    2 16   -> 48   sym.imp.__libc_start_main
0x00000800    2 16   -> 48   loc.imp.__gmon_start__
0x00000810    2 16   -> 48   sym.imp.munmap
0x00000820    2 16   -> 48   sym.imp.mprotect
0x00000830    2 16   -> 48   sym.imp.exit
0x00000840    2 16   -> 48   sym.imp.sleep
0x00000850    2 16   -> 48   sym.imp.__cxa_finalize
0x00000860    5 96   -> 105  main
0x000008c9    1 41           entry0
0x000008f2    1 1            fcn.000008f2
0x00000900    4 44           sym.deregister_tm_clones
0x00000930    4 60           sym.register_tm_clones
0x00000970    5 50           sym.__do_global_dtors_aux
0x000009b0    4 53   -> 46   sym.frame_dummy
0x000009f0    1 36           sym.alloc_page
0x00000a20    1 20           sym.make_page_executable
0x00000a40    1 15           sym.free_page
0x00000a50    3 47           sym.read_byte
0x00000a80    4 48           sym.read_n
0x00000ab0    1 15           sym.read_inst
0x00000ac0    3 153          sym.do_test
0x00000b60    4 101          sym.__libc_csu_init
0x00000bd0    1 2            sym.__libc_csu_fini
0x00000bd2    1 11           fcn.00000bd2
0x00000bdd    1 30           fcn.00000bdd
{{< /highlight >}}

> `afl` command stands for "analyze function list". In short, to print the functions detected by r2.

As you will see, there is a lot of functions we need to check (at least the names give an idea of what they are used for).  
Lets start with the `main` function.

{{< highlight r2 "hl_lines=23 25" >}}
[0x000008c9]> pdf @ main
            ;-- section_end..plt:
            ;-- section..text:
            ;-- main:
┌ (fcn) main 105
│   main ();
│              ; DATA XREF from 0x000008e6 (entry0)
│           0x00000860      55             push rbp                    
│           0x00000861      488d357c0300.  rsi = str.initializing_prof... 
│           0x00000868      ba14000000     edx = 0x14                  
│           0x0000086d      bf01000000     edi = 1                     
│           0x00000872      4889e5         rbp = rsp                   
│           0x00000875      e836ffffff     sym.imp.write ()
│           0x0000087a      4883f814       var = rax - 0x14            
│       ┌─< 0x0000087e      7407           if (!var) goto 0x887        ; unlikely
│       │      ; JMP XREF from 0x000008b5 (main)
│      ┌──> 0x00000880      31ff           edi = 0                     
│      |│ ; void exit(int status)
│      |│   0x00000882      e8a9ffffff     sym.imp.exit ()             
│      ↑│      ; JMP XREF from 0x0000087e (main)
│      |└─> 0x00000887      bf05000000     edi = 5                     
│      |  ; int sleep(int s)
│      |    0x0000088c      e8afffffff     sym.imp.sleep ()            
│      |    0x00000891      bf1e000000     edi = 0x1e                  
│      |    0x00000896      e835ffffff     sym.imp.alarm ()
│      |    0x0000089b      488d35570300.  rsi = str.ready_n 
│      |    0x000008a2      ba06000000     edx = 6                     
│      |    0x000008a7      bf01000000     edi = 1                     
│      |    0x000008ac      e8fffeffff     sym.imp.write ()            
│      |    0x000008b1      4883f806       var = rax - 6               
│      └──< 0x000008b5      75c9           if (var) goto 0x880         ; likely
└           0x000008b7      660f1f840000.                         
│              ; JMP XREF from 0x000008c7 (main)
│       ┌─> 0x000008c0      31c0           eax = 0
│       |   0x000008c2      e8f9010000     sym.do_test ()
│       └─< 0x000008c7      ebf7           goto 0x8c0     
{{< /highlight >}}

> `pdf` means **p**rint **d**isassemble **f**unction. Adding `@ main` we are telling radare which function we want to see.

There are two functions here we want to get rid of: `sleep` which is the one we were looking for and another one which, aparently, setup an alarm. If you wait 0x1e (oops, sorry 30 seconds :smile: ) you will see that this `alarm` function will end the process. Let's patch it too.

{{< highlight r2 "hl_lines=24 25 26 27 28 30 31 32 33 34" >}}
[0x000008c9]> wao nop @ 0x0000088c
[0x000008c9]> wao nop @ 0x00000896
[0x000008c9]> pdf @ main
            ;-- section_end..plt:
            ;-- section..text:
            ;-- main:
┌ (fcn) main 105
│   main ();
│              ; DATA XREF from 0x000008e6 (entry0)
│           0x00000860      55             push rbp                    
│           0x00000861      488d357c0300.  rsi = str.initializing_prof... 
│           0x00000868      ba14000000     edx = 0x14                  
│           0x0000086d      bf01000000     edi = 1                     
│           0x00000872      4889e5         rbp = rsp                   
│           0x00000875      e836ffffff     sym.imp.write ()
│           0x0000087a      4883f814       var = rax - 0x14            
│       ┌─< 0x0000087e      7407           if (!var) goto 0x887        ; unlikely
│       │      ; JMP XREF from 0x000008b5 (main)
│      ┌──> 0x00000880      31ff           edi = 0                     
│      |│ ; void exit(int status)
│      |│   0x00000882      e8a9ffffff     sym.imp.exit ()             
│      ↑│      ; JMP XREF from 0x0000087e (main)
│      |└─> 0x00000887      bf05000000     edi = 5                     
│      |    0x0000088c      90                                         
│      |    0x0000088d      90                                         
│      |    0x0000088e      90                                         
│      |    0x0000088f      90                                         
│      |    0x00000890      90                                         
│      |    0x00000891      bf1e000000     edi = 0x1e                  
│      |    0x00000896      90                                         
│      |    0x00000897      90                                         
│      |    0x00000898      90                                         
│      |    0x00000899      90                                         
│      |    0x0000089a      90 
│      |    0x0000089b      488d35570300.  rsi = str.ready_n 
│      |    0x000008a2      ba06000000     edx = 6                     
│      |    0x000008a7      bf01000000     edi = 1                     
│      |    0x000008ac      e8fffeffff     sym.imp.write ()            
│      |    0x000008b1      4883f806       var = rax - 6               
│      └──< 0x000008b5      75c9           if (var) goto 0x880         ; likely
└           0x000008b7      660f1f840000.    
│              ; JMP XREF from 0x000008c7 (main)
│       ┌─> 0x000008c0      31c0           eax = 0
│       |   0x000008c2      e8f9010000     sym.do_test ()
│       └─< 0x000008c7      ebf7           goto 0x8c0
{{< /highlight >}}

> `wao nop` assembles the nop opcode (which is `90` in hexadecimal) and writes it as many times as needed to overwrite the entire destination opcode. Nop means "**N**o **OP**eration".

Once we have patched them, we could continue checking the protections of the binary. This can be done through [checksec](https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec) script or with the r2 suite itself.

<table class="hmg">
    <tr>
        <td>
{{< highlight bash "hl_lines=6 7" >}}
$ checksec inst_prof 
[*] '/root/inst_prof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
{{< /highlight >}}
        </td>
        <td>
{{< highlight r2 "hl_lines=6 7" >}}
[0x000008c9]> i~true
iorw     true
havecode true
linenum  true
lsyms    true
nx       true
pic      true
relocs   true
va       true
{{< /highlight >}}
        </td>
        <td>
{{< highlight r2 "hl_lines=5 6" >}}
$ rabin2 -I inst_prof | grep true
havecode true
linenum  true
lsyms    true
nx       true
pic      true
relocs   true
va       true
{{< /highlight >}}
        </td>
    </tr>
</table>

What matters here is the `NX` and `PIE` flags.

1. `NX` is telling us that there are memory sections marked as Non-eXecutable: even if we are lucky enough to insert opcodes in some part of the memory we will need that part of the memory to be marked as executable.  
2. `PIE` tells us that the executable will be load in a randomly aligned address, so we will not be able to use fixed memory addresses to call functions.

Okay! 
We can start analyzing the binary flow. We can now move to the last part of the `main` function, right after the patched calls.

{{< highlight r2 "hl_lines=3" >}}
│              ; JMP XREF from 0x000008c7 (main)
│       ┌─> 0x000008c0      31c0           eax = 0
│       |   0x000008c2      e8f9010000     sym.do_test ()
│       └─< 0x000008c7      ebf7           goto 0x8c0
{{< /highlight >}}

Just an infinite loop to a function called `sym.do_test`. Unless there is some logic inside `sym.do_test` to end the program (like an `exit` function) it could never end!

Are not you curious about its content?

{{< highlight r2 "hl_lines=12 14 25 27 33 47 56" >}}
[0x000008c9]> pdf @ sym.do_test
┌ (fcn) sym.do_test 153
│   sym.do_test ();
│           ; var int local_18h @ rbp-0x18
│              ; CALL XREF from 0x000008c2 (main)
│           0x00000ac0      55             push rbp
│           0x00000ac1      31c0           eax = 0
│           0x00000ac3      4889e5         rbp = rsp
│           0x00000ac6      4154           push r12
│           0x00000ac8      53             push rbx
│           0x00000ac9      4883ec10       rsp -= 0x10
│           0x00000acd      e81effffff     sym.alloc_page ()
│           0x00000ad2      4889c3         rbx = rax
│           0x00000ad5      488d05240100.  rax = obj.template
│           0x00000adc      488d7b05       rdi = [rbx + 5]
│           0x00000ae0      488b10         rdx = qword [rax]
│           0x00000ae3      488913         qword [rbx] = rdx
│           0x00000ae6      8b5008         edx = dword [rax + 8]
│           0x00000ae9      895308         dword [rbx + 8] = edx
│           0x00000aec      0fb7500c       edx = word [rax + 0xc]
│           0x00000af0      0fb6400e       eax = byte [rax + 0xe]
│           0x00000af4      6689530c       word [rbx + 0xc] = dx
│           0x00000af8      88430e         byte [rbx + 0xe] = al
│         ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x00000afb      e8b0ffffff     sym.read_inst ()
│           0x00000b00      4889df         rdi = rbx
│           0x00000b03      e818ffffff     sym.make_page_executable ()
│           0x00000b08      0f31          
│           0x00000b0a      48c1e220       rdx <<<= 0x20
│           0x00000b0e      4989c4         r12 = rax
│           0x00000b11      31c0           eax = 0
│           0x00000b13      4909d4         r12 |= rdx
│           0x00000b16      ffd3           rbx ()
│           0x00000b18      0f31               
│           0x00000b1a      bf01000000     edi = 1
│           0x00000b1f      48c1e220       rdx <<<= 0x20
│           0x00000b23      488d75e8       rsi = [local_18h]
│           0x00000b27      4809c2         rdx |= rax
│           0x00000b2a      4c29e2         rdx -= r12
│           0x00000b2d      488955e8       qword [local_18h] = rdx
│           0x00000b31      ba08000000     edx = 8
│           0x00000b36      e875fcffff     sym.imp.write ()
│           0x00000b3b      4883f808       var = rax - 8
│       ┌─< 0x00000b3f      7511           if (var) goto 0xb52
│       │   0x00000b41      4889df         rdi = rbx
│       │ ; void free(void *ptr)
│       │   0x00000b44      e8f7feffff     sym.free_page ()
│       │   0x00000b49      4883c410       rsp += 0x10
│       │   0x00000b4d      5b             pop rbx
│       │   0x00000b4e      415c           pop r12
│       │   0x00000b50      5d             pop rbp
│       │   0x00000b51      c3             
│       │      ; JMP XREF from 0x00000b3f (sym.do_test)
│       └─> 0x00000b52      31ff           edi = 0
│         ; void exit(int status)
└           0x00000b54      e8d7fcffff     sym.imp.exit ()
{{< /highlight >}}

Which are your first thoughts about the highlighted lines? mines are:

1. `sym.alloc_page ()`: We will start by this one. That name suggests that it will, somehow, reserve some memory right?  
2. `obj.template`: what is that? a template? of what?  
3. `sym.read_inst ()`: mmmh ok, it suggests that is going to read an instruction.  
4. `sym.make_page_executable ()`: aparently this is the one in charge of making a page executable (probably it will be used for the recently-created page).  
5. `rbx ()`: it calls a zone of memory whose address is stored in `rbx` register. What is most logical is to think that this address will be the address of the page which has already allocated (through `sym.alloc_page`) and marked as executable (through `sym.make_page_executable`)
6. `sym.free_page ()` or `sym.imp.exit ()`: Depending on the condition `do_test` will be called again (so this flow will happen once more) or `exit` will be the chosen one, causing the process to be terminated.  

---

Ok, with a single one-shot to `do_test` function we've got a picture of the flow. Let's dig a bit more into the code to get a better understanding of how it is done.

##### sym.alloc_page

{{< highlight r2 "hl_lines=14" >}}
[0x000009f0]> pdf @ sym.alloc_page 
┌ (fcn) sym.alloc_page 36
│   sym.alloc_page ();
│       ↑      ; CALL XREF from 0x00000acd (sym.do_test)
│       |   0x000009f0      55             push rbp                    
│       |   0x000009f1      4531c9         r9d = 0                     
│       |   0x000009f4      41b8ffffffff   r8d = 0xffffffff            ; -1 
│       |   0x000009fa      b922000000     ecx = 0x22                  ; '"' 
│       |   0x000009ff      ba03000000     edx = 3                     
│       |   0x00000a04      be00100000     esi = 0x1000                
│       |   0x00000a09      4889e5         rbp = rsp                   
│       |   0x00000a0c      31ff           edi = 0                     
│       |   0x00000a0e      5d             pop rbp                     
└       └─< 0x00000a0f      e9acfdffff     goto sym.imp.mmap           ; sym.imp.mmap
{{< /highlight >}}

It is calling an imported function called `mmap`. With a simple `man mmap` (or just looking at google) we can figure out which arguments it receives. The definition of the function was taken from manual. 

```vim
$ man mmap
void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
```

If we apply the calling convention we mentioned at the beginning of the post we will get that the function is being called like this:
```vim
rax = mmap(0, 0x1000, 3, 0x22, -1, 0);
```

Basically it is:

1. Creating a memory region somewhere.  
2. With a size of `0x1000` bytes.  
3. That memory region will have **read** and **write** permissions. This come from "or-ing":  
`PROT_READ | PROT_WRITE = 0x1 | 0x2 = 0x3`  
4. The changes in memory are not visible to others processes and not are not backed by any file. Again, this explanation comes from "or-ing":  
`MAP_PRIVATE | MAP_ANONYMOUSE = 0x20 | 0x2 = 0x22`.  


##### obj.template

Obviously, it is allocating some space in memory to put something in there. `obj.template` has all the odds to has something to do with this. Lets see what is at that address:

{{< highlight r2 "hl_lines=4 9 10" >}}
[0x000009f0]> pd 8 @ obj.template 
            ;-- template:
               ; DATA XREF from 0x00000ad5 (sym.do_test)
            0x00000c00      b900100000     ecx = 0x1000                
        ┌─> 0x00000c05      90                                         
        |   0x00000c06      90                                         
        |   0x00000c07      90                                         
        |   0x00000c08      90                                         
        |   0x00000c09      83e901         ecx -= 1                    
        └─< 0x00000c0c      75f7           if (var) goto 0xc05
            0x00000c0e      c3                                         
[0x000009f0]> ? 0x1000
4096 0x1000 010000 4K 0000:0000 4096 "\x10" 0001000000000000 4096.0 4096.000000f 4096.000000
{{< /highlight >}}

> `pd 8 @ obj.template` indicates radare to print 8 asm instructions starting from `obj.template` address.

Interesting, it is just a small loop, which is going to iterate `0x1000 = 4096` times. But thats all, because inside of the loop there is only NOPs opcodes.

Now that we know what is in there, we can keep going with the flow we were explaining before. Right after the `sym.alloc_page` call, there are the following instructions. I will explain line-by-line what they do.

```r2
│           0x00000acd      e81effffff     sym.alloc_page ()
│           0x00000ad2      4889c3         rbx = rax
│ ; The address of the recently-allocated page is saved in rbx (remember that by default
│ ; the returned value of sym.alloc_page (and every function which follows the
│ ; previously commented convention) is stored in rax).
│           0x00000ad5      488d05240100.  rax = obj.template
│ ; It copies the address of the loop-template we have just described in rax.
│           0x00000adc      488d7b05       rdi = [rbx + 5]
│ ; It adds 5 to the address of rbx and saves the result in rdi. Note that rdi wont be used
│ ; in the following instrucctions so we can assume it could be the argument of the next
│ ; function. Remember it.
│           0x00000ae0      488b10         rdx = qword [rax]
│ ; the first 8 bytes (a qword) rax is pointing to are copied in rdx.
│ ; If you look again to obj.template you will realize that it is copying
│ ; its first 8 bytes:
│ ;     b900100000  ecx = 0x1000
│ ;     90          nop
│ ;     90          nop
│ ;     90          nop
│ ; 5 bytes which defines the first instruction: ecx = 0x1000
│ ; and another extra 3 bytes (3 NOPs instructions).
│           0x00000ae3      488913         qword [rbx] = rdx
│ ; After saving those 8 bytes in the rdx register, it copies them to the address 
│ ; rbx is pointing to (which is the beginning of the allocated page).
│           0x00000ae6      8b5008         edx = dword [rax + 8]
│ ; It copies 4 bytes (a dword) of the content of the address of rax+8.
│ ; These bytes are 90 83 e9 01 and form the following instructions:
│ ;     90          nop
│ ;     83e901      ecx -= 1
│ ; In short, it is copying the last nop instruction (there were 4) 
│ ; and new instruction in the edx register.
│           0x00000ae9      895308         dword [rbx + 8] = edx
│ ; And again it is saving those two instructions in memory, next to the previously ones. 
│           0x00000aec      0fb7500c       edx = word [rax + 0xc]
│           0x00000af0      0fb6400e       eax = byte [rax + 0xe]
│           0x00000af4      6689530c       word [rbx + 0xc] = dx
│           0x00000af8      88430e         byte [rbx + 0xe] = al
│ ; The rest instructions do the same operation but with less data: 2 bytes (a word)
│ ; and 1 byte respectively. Those bytes represent the last 2 instructions:
│ ;     75f7        if (var) goto 0x7ff2c49f0005
│ ;     c3          ret
│           0x00000afb      e8b0ffffff     sym.read_inst ()
```
> If you do not trust me (yeah dont do it) you can check these explanations executing each instruction. For that you first need to open a new radare session and set some breakpoints to reach that memory zone. The fastest way to do it is using the following command.
```bash
$ r2 -Ad -c 'dcu main; db `/c mov rbx, rax`; dc; Vpp' inst_prof
```
> Ok, that is a long cmd right? but you will see how much interesting it is.
> First we tell r2 to analyze the binary and open it in **debug** mode `-Ad`.
> Thats not enough for us and we ask him to execute the following commands (`-c`).  
>   
> 1.   `dcu main` executes the process until arrive main function. When all the functions will be mapped in memory. 
> 2.   ``db `/c mov rbx, rax` `` Once all the functions are mapped in memory, radare searches for the instruction "mov rbx, rax" and create a breakpoint at its address.  
> 3.   `dc; Vpp` executes the process again (which will cause the breakpoint to be hit) and swap radare to Visual mode with his second view rotation.
>   
> Once there, you can press F8 while looking carefully the value of the registers and the memory pointed by rbx with: `px 10 @ rbx`.

In summary, the instructions between `sym.alloc_page` and `sym.read_inst` functions are used to copy the instructions from the `obj.template` into the allocated page. Now is the turn of `sym.read_inst` function.

##### sym.read_inst

Lets devour `sym.read_inst` now!
Remember the `rdi = [rbx + 5]` instruction I told you to remember before? Look where it points to.
{{< highlight r2 "hl_lines=5" >}}
[0x55cfea0bcacd]> pd 6 @ rdi -5
            ;-- rbx:
            0x7f2d9bae5000      b900100000     ecx = 0x1000
            ;-- rdi:
            0x7f2d9bae5005      90                                    
            0x7f2d9bae5006      90                                     
            0x7f2d9bae5007      90                                     
            0x7f2d9bae5008      90                                     
            0x7f2d9bae5009      83e901         ecx -= 1
{{< /highlight >}}

Its pointing to the first `nop` of the copy of `obj.template` which is in the recently-allocated page.
I bet there is where `read_inst ()` is going to store the read instruction.

{{< highlight r2 "hl_lines=6 9" >}}
[0x000009f0]> pdf @ sym.read_inst 
┌ (fcn) sym.read_inst 15
│   sym.read_inst ();
│       ↑      ; CALL XREF from 0x00000afb (sym.do_test)
│       |   0x00000ab0      55             push rbp                    
│       |   0x00000ab1      be04000000     esi = 4                     
│       |   0x00000ab6      4889e5         rbp = rsp                   
│       |   0x00000ab9      5d             pop rbp                     
└       └─< 0x00000aba      e9c1ffffff     goto sym.read_n             
{{< /highlight >}}

Aparently, `sym.read_inst` is nothing but a wrapper of `sym.read_n`. It just adds a second argument. Now we have:

1. rdi = addr of first nop
2. rsi = 4

That 4 is probably going to be the number of bytes being copied. It makes sense since there are exactly 4 nops instructions to be overwritten which occupy exactly 4 bytes in total. 

{{< highlight r2 "hl_lines=17 18" >}}
[0x000009f0]> pdf @ sym.read_n
┌ (fcn) sym.read_n 48
│   sym.read_n ();
│              ; JMP XREF from 0x00000aba (sym.read_inst)
│           0x00000a80      55             push rbp                    
│           0x00000a81      4885f6         var = rsi & rsi             
│           0x00000a84      4889e5         rbp = rsp                   
│           0x00000a87      4154           push r12                    
│           0x00000a89      4c8d2437       r12 = [rdi + rsi]           
│           0x00000a8d      53             push rbx                    
│           0x00000a8e      4889fb         rbx = rdi                   
│       ┌─< 0x00000a91      7418           if (!var) goto 0xaab
│       │   0x00000a93      0f1f440000                                 
│       │      ; JMP XREF from 0x00000aa9 (sym.read_n)
│      ┌──> 0x00000a98      31c0           eax = 0                     
│      |│   0x00000a9a      4883c301       rbx += 1                    
│      |│   0x00000a9e      e8adffffff     sym.read_byte ()            
│      |│   0x00000aa3      8843ff         byte [rbx - 1] = al         
│      |│   0x00000aa6      4c39e3         var = rbx - r12             
│      └──< 0x00000aa9      75ed           if (var) goto 0xa98
│       │      ; JMP XREF from 0x00000a91 (sym.read_n)
│       └─> 0x00000aab      5b             pop rbx                     
│           0x00000aac      415c           pop r12                     
│           0x00000aae      5d             pop rbp                     
└           0x00000aaf      c3                                         
{{< /highlight >}}

This loop seems a bit confusing, but it is just iterating 4 times (going from -3 to 0) calling `sym.read_byte()` and retrieving `1 byte` of the input string. Then it just stores it overwriting one of the previously commented `nop` opcodes.

{{< highlight r2 "hl_lines=14" >}}
[0x000009f0]> pdf @ sym.read_byte
┌ (fcn) sym.read_byte 47
│   sym.read_byte ();
│           ; var int local_1h @ rbp-0x1
│              ; CALL XREF from 0x00000a9e (sym.read_n)
│           0x00000a50      55             push rbp                    
│           0x00000a51      31ff           edi = 0                     
│           0x00000a53      ba01000000     edx = 1                     
│           0x00000a58      4889e5         rbp = rsp                   
│           0x00000a5b      4883ec10       rsp -= 0x10                 
│           0x00000a5f      488d75ff       rsi = [local_1h]            
│           0x00000a63      c645ff00       byte [local_1h] = 0         
│         ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x00000a67      e874fdffff     sym.imp.read ()             
│           0x00000a6c      4883f801       var = rax - 1               
│       ┌─< 0x00000a70      7506           if (var) goto 0xa78         ; likely
│       │   0x00000a72      0fb645ff       eax = byte [local_1h]       
│       │   0x00000a76      c9                                         
│       │   0x00000a77      c3                                         
│       │      ; JMP XREF from 0x00000a70 (sym.read_byte)
│       └─> 0x00000a78      31ff           edi = 0                     
│         ; void exit(int status) ; sym.imp.exit
└           0x00000a7a      e8b1fdffff     sym.imp.exit ()             
[0x000009f0]> 
{{< /highlight >}}

And nothing interesting inside `sym.read_byte`, it is just another wapper to call `read` with the following fixes values:

1. `rdi = 0` which means "read from the standard input" (basically what the user presses in the shell).
2. `rsi` is an address of a variable where `read` will store the input.
3. `rdx = 1` the expected length of the input.

sigh, this is being long. To check all this out we can start radare with some random input and execute the binary until the instruction right after `read_inst` call. Once there, we only need to check if the input string are there instead of the nop opdes

{{< highlight r2 "hl_lines=23 25" >}}
$ r2 -Ad -R 'stdin="AAAA"' -c 'dcu `/r sym.read_inst~[1]`; px 4 @r:rbx+5; dso; px 4 @r:rbx+5;' inst_prof
{{< /highlight >}}

> `-Ad`: Again analyze and debug it.  
> `-R 'stdin="AAAA"'`: To pass AAAA as the standard input.  
> `-c `: To execute commands once r2 has ended loading the binary.  
> ``dcu `/r sym.read_inst~[1]` ``: `/r sym.read_inst` will return all the calls to that function. From those results, we filter the address with `~[1]`. Knowing the address we can use `dcu address` which will execute the process until that address.  
> `px 4 @r:rbx+5`: prints 4 hexadecimal values from the address of `rbx+5` which is the address where the input is going to be written.  
> `dso`: **D**ebug **S**tep **O**ver. To execute the entire `sym.read_inst` flow but without going into it.  
> `px 4 @r:rbx+5`: print the same 4 bytes again.  

This way we can check if the write has been done correctly.

##### sym.make_page_executable
As the title suggests the purpose of this function is to make a page executable. Of course, this is the page where we have copied the `obj.template` and overwritten the nop opcodes bytes (those 90 90 90 90) with our own 4 byte input.

{{< highlight r2 "hl_lines=10" >}}
[0x000008c9]> pdf @ sym.make_page_executable 
┌ (fcn) sym.make_page_executable 20
│   sym.make_page_executable ();
│       ↑      ; CALL XREF from 0x00000b03 (sym.do_test)
│       |   0x00000a20      55             push rbp                    
│       |   0x00000a21      ba05000000     edx = 5                     
│       |   0x00000a26      be00100000     esi = 0x1000                
│       |   0x00000a2b      4889e5         rbp = rsp                   
│       |   0x00000a2e      5d             pop rbp                     
└       └─< 0x00000a2f      e9ecfdffff     goto sym.imp.mprotect
{{< /highlight >}}

As previously seen, the call is following the commented convention. It is using the registers `rdi` (it was set one instruction before the call to `sym.make_page_executable` in `0x00000ad2`), `rsi` and `rdx`. Three arguments. The entire call could me summarize like this:
```vim
int mprotect(address_to_copied_template, 0x1000, PROT_EXEC);
```
At this point no further explanation is needed on this function, right?
It is just saying: "Hey, please, from this address, count 0x1000 bytes and make the entire region executable".

So now our input bytes could be executed, which is the purpose of the following entry: `rbx()`

##### rbx ()
So... (cheer up we are finishing!) `rbx` register contains the address of the first instruction of the `obj.template` duplicate. Remember that this duplicate does not contain `nop` instructions anymore but our input of 4 bytes.

It will **execute** something we provide to it!

We can not create a 4-byte-lengh shellcode though, but hey we will deal with it later.

{{< highlight r2 "hl_lines=14 18" >}}
0x7fdeaba18000 240 /root/inst_prof]> ?0;f tmp;s.. @ rbx                                                                                            
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7fff40b82ac8  189b 0f42 cf55 0000 b08c 80ab de7f 0000  ...B.U..........
0x7fff40b82ad8  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fff40b82ae8  c998 0f42 cf55 0000 002b b840 ff7f 0000  ...B.U...+.@....
0x7fff40b82af8  c798 0f42 cf55 0000 609b 0f42 cf55 0000  ...B.U..`..B.U..
 rax 0x00000000           rbx 0x7fdeaba18000       rcx 0x7fdeab53e497
 rdx 0x8ec00000000         r8 0xffffffffffffffff    r9 0x00000000
 r10 0x00000487           r11 0x00000202           r12 0x8ecf3e8e3d8
 r13 0x7fff40b82be0       r14 0x00000000           r15 0x00000000
 rsi 0x00001000           rdi 0x7fdeaba18000       rsp 0x7fff40b82ac8
 rbp 0x7fff40b82af0       rip 0x7fdeaba18000       rflags 1PI
orax 0xffffffffffffffff
            ;-- rbx:
            ;-- rdi:
            ;-- rip:
            0x7fdeaba18000      b900100000     ecx = 0x1000            ; rsi
        ┌─> 0x7fdeaba18005      4141414183e9.  r9d -= 1                ; orax
        └─< 0x7fdeaba1800c      75f7           if (var) goto 0x7fdeaba18005
            0x7fdeaba1800e      c3             
{{< /highlight >}}

##### sym.free_page

The last function is `sym.free_page` and its the one in charge of deallocating the page the process was using during its entire flow execution.

{{< highlight r2 "hl_lines=9" >}}
[0x7fc9a5eeac20]> pdf @ sym.free_page 
┌ (fcn) sym.free_page 15
│   sym.free_page ();
│       ↑      ; CALL XREF from 0x5603de075b44 (sym.do_test)
│       |   0x5603de075a40      55             push rbp                
│       |   0x5603de075a41      be00100000     esi = 0x1000            
│       |   0x5603de075a46      4889e5         rbp = rsp               
│       |   0x5603de075a49      5d             pop rbp                 
└       └─< 0x5603de075a4a      e9c1fdffff     goto sym.imp.munmap
{{< /highlight >}}

Have in mind that this step is quite important. Until this point, the process has configured a memory area with:

1. **Write** privileges (Do you remember those `PROT_READ | PROT_WRITE` stuff right?)
2. And **execution** privileges (using the `sym.make_page_executable`).

It is not common to find memory regions with both privileges, because someone could use them to store unwanted stuff (like a shellcode :grin: ) and execute it. 
That is the main reason why it is a good idea to deallocate the page. 

{{< highlight r2 "hl_lines=21 22" >}}
$ r2 -Ad -R 'stdin="AAAA"' -c 'dcu `/r sym.make_page_executable~[1]`; dm~unk2; dso; dm~unk2;' inst_prof
Process with PID 11008 started...
= attach 11008 11008
bin.baddr 0x55e96f469000
Using 0x55e96f469000
Assuming filepath /root/inst_prof
asm.bits 64
[x] Analyze all flags starting with sym. and entry0 (aa)
TODO: esil-vm not initialized
[Cannot determine xref search boundariesr references (aar)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
ptrace (PT_ATTACH): Operation not permitted
= attach 11008 11008
[0x7ff8a50b5ff0-0x7ff8a50b6000] Continue until 0x55e96f469b03 using 1 bpsize
initializing prof...ready
hit breakpoint at: 55e96f469b03
hit breakpoint at: 55e96f469b08
usr    16K 0x00007ff8a52b2000 - 0x00007ff8a52b6000 s -rw- unk2 unk2
usr     4K 0x00007ff8a52b2000 - 0x00007ff8a52b3000 s -r-x unk2 unk2
 -- Helping siol merge? No way, that would be like.. way too much not lazy. - vifino
{{< /highlight >}}

> The command used is pretty similar to the previous one  
> `-Ad`: Again analyze and debug it.  
> `-R 'stdin="AAAA"'`: To pass AAAA as the standard input.  
> `-c `: To execute commands once r2 has ended loading the binary.  
> ``dcu `/r sym.make_page_executable~[1]` ``: `/r sym.make_page_executable` will return all the calls to that function. From those results, we filter the address with `~[1]`. Knowing the address we can use `dcu address` which will execute the process until that address.  
> `dm~unk2`: `dm` returns the mapping of the memory of the process. We are filtering the results because we already know that the interesting one has the `unk2` string.  
> `dso`: **D**ebug **S**tep **O**ver. To execute the entire `sym.make_executable` flow but without going into it.  
> `dm~unk2`: to print the map of the region we are interested at, again.  


We are printing the maps of the process before and after the call to `sym.make_page_executable`. When writting our input, the memory area has the write privilege (`-rw-`), but 
after the call to `sym.make_page_executable` those permissions has been changed to `-r-x` which is perfect because otherwise the `rbx()` call would fail.

---

Finally! we ended describing the entire flow of the program step by step.
As this article is getting very long I have decided to stop writing here and to explain the exploitation phase in part 2 (**comming soon**).

Congratz for reaching the end of the first part. Reading and understanding it must have been almost as tough as writing it. However, if something was not clear I recommend to re-read it that part again. Otherwise, you will likely get lost on the next part.

<table class="hmg">
    <tr>
        <td>
            <h3>References</h3>
            <ol>
                <li><a href="https://github.com/radare/radare2">radare2</a> - To analyze the binary.</li>
                <li><a href="https://binarystud.io/googlectf-2017-inst-prof-152-final-value.html">BinaryStud.io</a> - Another solution using r2!</li>
                <li><a href="https://en.wikipedia.org/wiki/Opcode) and [Bit NX] (https://es.wikipedia.org/wiki/Bit_NX">OPCode</a></li>
                <li><a href="https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec">CheckSec</a></li>
            </ol>
        </td>
        <td>
            <h3>Some thanks</h3>
            <ol>
                <li><a href="https://github.com/trufae">@pancake</a> - For reviewing this article and pointing some improvements on it.</li>
                <li><a href="https://github.com/TobalJackson/radare2-pygments-lexer">@TobalJackson</a> - For his lexer for r2 highlighting in hugo engine.</li>
            </ol>
        </td>
    </tr>
</table>