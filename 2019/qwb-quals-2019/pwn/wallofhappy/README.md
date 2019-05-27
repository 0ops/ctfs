WallOfHappy is a staticly linked program. The user program itself is not difficult to be found out. Main logic of it is shown as follows.

```C
__int64 __fastcall sub_4ED15C(__int64 a1, __int64 a2)
{
  __int64 result; // rax
  char *v3; // rax
  __int64 v4; // rsi
  char stack_buf[1096]; // [rsp+0h] [rbp-460h]
  int v6; // [rsp+448h] [rbp-18h]
  __int64 v7; // [rsp+458h] [rbp-8h]

  result = wtfwtf_4EC97C(a1, a2);
  v7 = result;
  if ( result )
  {
    memset(stack_buf, 0, sizeof(stack_buf));
    v6 = 0;
    v3 = &stack_buf[strlen(stack_buf)];
    *(_QWORD *)v3 = 'paH ruoY';
    *((_QWORD *)v3 + 1) = 'e ssenip';
    *((_QWORD *)v3 + 2) = ': slauq';
    v4 = v7;
    plt_strcat_400490((__int64)stack_buf, v7);
    result = printf_4F4010((__int64)stack_buf, v4);
  }
  return result;
}
```

Function `wtfwtf_4EC97c` will dispatch according to the user input number and 8-bytes signature, and finally return a corresponding constant string. The difficult thing here is lots of similar function as follows.

```C
_QWORD *sub_400D4D()
{
  char *buf; // ST18_8
  _QWORD *result; // rax
  _QWORD *v2; // [rsp+10h] [rbp-20h]

  buf = (char *)libc_malloc_500880(0x3E8uLL);
  v2 = (_QWORD *)libc_malloc_500880(0x3E8uLL);
  libc_read_52A660(0, buf, 0x3E7uLL);
  *v2 = *(_QWORD *)"VRovqOtGChWfVbAqzuhTMfnPzTViUEWcWwZMeRfjOiatTxTxjwTdLiZvIXkDfoBLLeZYtfuauqAMlJiddvWHBgQXPApNPNVfiQmyU"
                   "RfaIMGoSOgLFEfdLcDPtvvRgbjIdnrqqaLtPgOprWYkSiXuEzSHtQURpjhpYeOSFqlQDJIYqAWIdlKuWbaeKllvflyZiIWeSJrpGa"
                   "VybWYWnQxQmnICPYgTOkqEImfkacMzykzVhuqThfQORBQkOEEnOuhUZwDaikPkLqgdFjQnGqqmZBhITKIAZZvTerOdpyZhlWpHtgk"
                   "WXQaBuLQHHYmnZtIUHFrofrDjZzYfHbIUhHXnxkAPXOtANnGMkOqKtxVXJKChJcqJBieFbRXVSOeWkIdnpAYpiTjEOvZbENKLSQgw"
                   "nwJNCkTxrPqsWnhWfmSzCvfMOLtfOvSbSRMTIiHMnTgwlZiIsjydgtUVpxEQzrddHEGVmoQSyoPSxaUIckBDcrCwWbYFqYoBuhwwH"
                   "FlTYBXKsPdyOYeAnNMIVqZXTrlGIgRaJgifykOvHxToNkdxcaEAMXpDTmPhdrYgYJAUYFPKTdJDsIAjygXUQCFZRItfhpZnPqrBsL"
                   "wjsxDKbPqtpzshasqVUSseAidMzFpBEWsBUyvLYkJVvQUWFWJYRjYxmzEeKVpGySfgkYWXSFarsiRrFBHSItSIJZFZHBupHzNaUUO"
                   "FewifFykUcGPPwbDCMEKVAIiHQGljkZhynIqQIbrsGWOeppygTQkPzcNIoAawIpdwDZItHoOzidZnMVLYLidCHoeFkUDwsYBbpeHN"
                   "saDjsRlxhjbUXVjcCmEFEmmseAhJTPGoTFmCYtlJWvDKzlZFRrcsOgyKYwhzsiXFSUPvJonEfuuwRRvqqrWfiYpmCHfdetJWzfbRK"
                   "LwJHbLLqPSfsNyGYensyDMElGJfpZWuKLnZuPCiyxvDwjpbEmuUcOwpGjtIkMURFUFOUFPEOVactSWxaNYsNUHKqukY";
  *(_QWORD *)((char *)v2 + 991) = *(_QWORD *)"sNUHKqukY";
  qmemcpy(
    (void *)((unsigned __int64)(v2 + 1) & 0xFFFFFFFFFFFFFFF8LL),
    (const void *)("VRovqOtGChWfVbAqzuhTMfnPzTViUEWcWwZMeRfjOiatTxTxjwTdLiZvIXkDfoBLLeZYtfuauqAMlJiddvWHBgQXPApNPNVfiQmyU"
                   "RfaIMGoSOgLFEfdLcDPtvvRgbjIdnrqqaLtPgOprWYkSiXuEzSHtQURpjhpYeOSFqlQDJIYqAWIdlKuWbaeKllvflyZiIWeSJrpGa"
                   "VybWYWnQxQmnICPYgTOkqEImfkacMzykzVhuqThfQORBQkOEEnOuhUZwDaikPkLqgdFjQnGqqmZBhITKIAZZvTerOdpyZhlWpHtgk"
                   "WXQaBuLQHHYmnZtIUHFrofrDjZzYfHbIUhHXnxkAPXOtANnGMkOqKtxVXJKChJcqJBieFbRXVSOeWkIdnpAYpiTjEOvZbENKLSQgw"
                   "nwJNCkTxrPqsWnhWfmSzCvfMOLtfOvSbSRMTIiHMnTgwlZiIsjydgtUVpxEQzrddHEGVmoQSyoPSxaUIckBDcrCwWbYFqYoBuhwwH"
                   "FlTYBXKsPdyOYeAnNMIVqZXTrlGIgRaJgifykOvHxToNkdxcaEAMXpDTmPhdrYgYJAUYFPKTdJDsIAjygXUQCFZRItfhpZnPqrBsL"
                   "wjsxDKbPqtpzshasqVUSseAidMzFpBEWsBUyvLYkJVvQUWFWJYRjYxmzEeKVpGySfgkYWXSFarsiRrFBHSItSIJZFZHBupHzNaUUO"
                   "FewifFykUcGPPwbDCMEKVAIiHQGljkZhynIqQIbrsGWOeppygTQkPzcNIoAawIpdwDZItHoOzidZnMVLYLidCHoeFkUDwsYBbpeHN"
                   "saDjsRlxhjbUXVjcCmEFEmmseAhJTPGoTFmCYtlJWvDKzlZFRrcsOgyKYwhzsiXFSUPvJonEfuuwRRvqqrWfiYpmCHfdetJWzfbRK"
                   "LwJHbLLqPSfsNyGYensyDMElGJfpZWuKLnZuPCiyxvDwjpbEmuUcOwpGjtIkMURFUFOUFPEOVactSWxaNYsNUHKqukY"
                 - ((char *)v2
                  - ((unsigned __int64)(v2 + 1) & 0xFFFFFFFFFFFFFFF8LL))),
    8LL * ((((_DWORD)v2 - (((_DWORD)v2 + 8) & 0xFFFFFFF8) + 999) & 0xFFFFFFF8) >> 3));
  if ( *v2 == *(_QWORD *)buf )
    result = v2;
  else
    result = 0LL;
  return result;
}
```

After observation, we found size of all the functions are same. We guess that the target vulnerable function maybe only vary in variables or constants. Thanks to my laziness, I found out `sub_4727AD` is varied just through simple `grep` and `wc -l` line by line, even without program analysis using IDAPython XD.

The difference in `sub_4727AD` from others is that it returns the user input buf not the constant string. So this is a *fsb* (Format String Bug).

But things didn't go that well. The user input buf is located in heap and copied to stack via `strcat`, so `\0` will terminate our input in stack, which means only one address value controlled by us may appear in stack, and more importantly, program will return after fsb. 

Our finally solution for the challenge : 
1. Leak address of heap and stack and rewrite function pointer in `fini_array` with entrypoint of `main`(leak and get another chance to do fsb).
2. Use fsb in printf to rewrite return address of itself with the gadget `xchg eax, esp; ret` address. Meanwhile make return value of printf (rax) be address of the input in heap (return value of `printf` is the number of characters printed).
3. rop to get shell.
