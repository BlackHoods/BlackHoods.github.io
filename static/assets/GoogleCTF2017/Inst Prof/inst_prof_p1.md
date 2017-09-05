## [GoogleCTF 2017](https://g.co/ctf)
#### Exploiting - Inst Prof

![inst_prof Description](assets/1-inst_prof_description.png)

In this [challenge](assets/inst_prof) we are given a binary that is running remotely at [inst-prof.ctfcompetition.com:1337](inst-prof.ctfcompetition.com:1337). Probably the flag will be in the server.
Let's see what this binary does.

![inst_prof executing](assets/2-inst_prof_executing.png)

If you execute it, you could realized that there is one delay of 5 seconds between "initializing prof..." and "ready" strings. I do not want to wait 5 seconds everytime I want to test something so lets patch it.

```bash
$ r2 -A -w inst_prof
[0x000008c9]> s main; Vp   # Cursor at main function, swap to Visual view. P rotates between several Visual views styles.
```

![inst_prof patching 1](assets/3-patching_sleep_and_alarm.png)

There are two functions interestings here: the sleep one we were looking for and another interesting one which aparently starts an alarm. If you wait 0x1e (oops, sorry 30 seconds) you will see that this alarm function will end the process. Let's patch it too.

```bash
[0x00000860]> wx 9090909090 @ 0x0000088c  # wx writes 5 times the NOP opcode (90) starting at 0x0000088c
[0x00000860]> wx 9090909090 @ 0x00000896  # same but starting at 0x00000896
[0x00000860]> pdf @ main                  # Print Dissasembly Function main.
```
![inst_prof patching 2](assets/4-patching_sleep_and_alarm_2.png)

Once we patch them, we can start checking the protections of the binary. This can be done through [checksec](https://raw.githubusercontent.com/slimm609/checksec.sh/master/checksec) script

![inst_prof checking protections](assets/5-protections_enabled.png)

or with r2.
![inst_prof checking protections 2](assets/6-protections_enabled_2.png)

What matters here is the NX and PIE flags.
1. NX is telling us that there are memory sections marked as Non-eXecutable: even if we are lucky enough to insert opcodes in some part of the memory we will need that this part of the memory is marked as executable.
2. PIE tells us that the executable will be load in a randomly aligned address, so we will not be able to use fixed memory addresses to call functions

Okay lets figure out what this binary does.

```bash
$ r2 -A inst_prof
[0x000008c9] > afl
```
We can see a list with the used functions along the binary flow. We will start analyzing the main function and explaining the flow from there.



```bash
[0x000008c9] > s main; Vp
```

![do_loop call](assets/7-function_do_loop.png)

After printing the previously commented messages, there is a loop in which a function named `do_loop` is called. What is done inside of it?
```bash

```

## References
1. https://binarystud.io/googlectf-2017-inst-prof-152-final-value.html
2. https://en.wikipedia.org/wiki/Opcode
3. https://es.wikipedia.org/wiki/Bit_NX
4. a
5. a
6. a
7. aa
8. a
9. a
10. 