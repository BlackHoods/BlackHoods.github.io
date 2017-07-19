from pwn import *

r = process("/usr/bin/r2 -d /media/sf_shared/CTFs/GoogleCTF2017/inst_prof")
r.interactive()
