from pwn import remote

conn = remote('127.0.0.1', 5009)

conn.recvuntil(b"Nombre 1 : ")
bin1 = conn.recvline().split()[0].decode('utf-8')
conn.recvuntil(b"Nombre 2 : ")
bin2 = conn.recvline().split()[0].decode('utf-8')

num1 = int(bin1, 2)
num2 = int(bin2, 2)

def solve_question(operation, result):
    conn.recvuntil(operation)
    conn.sendline(result)

and_result = format(num1 & num2, '08b').encode('utf-8')
solve_question(b"= ", and_result)

or_result = format(num1 | num2, '08b').encode('utf-8')
solve_question(b"= ", or_result)

add_result = format(num1 + num2, '08b').encode('utf-8')
solve_question(b"= ", add_result)

mul_result = format(num1 * num2, '08b').encode('utf-8')
solve_question(b"= ", mul_result)

left_shift_result = format(num1 << 2, '08b').encode('utf-8')
solve_question(b"= ", left_shift_result)

right_shift_result = format(num1 >> 2, '08b').encode('utf-8')
solve_question(b"= ", right_shift_result)

conn.interactive()
