## Chall

Only a single *QEMU* binary can be found in the downloaded file. Thus we need to use our own kernel image and file system to run. 

For the *QEMU* binary itself, there is a custom device, *qwb*, implementing a state machine to do encryption or decryption in AES or XOR way. Symbols of the *QEMU* binary is not stripped, and we can find the structure related to the device in IDA Pro as follows.

```
00000000 QwbState        struc ; (sizeof=0x2250, align=0x10, copyof_4601)
00000000 pdev            PCIDevice_0 ?
000008E0 mmio            MemoryRegion_0 ?
000009D0 thread          QemuThread_0 ?
000009D8 crypto_statu_mutex QemuMutex_0 ?
00000A08 crypto_buf_mutex QemuMutex_0 ?
00000A38 crypto          crypto_status ?
00002250 QwbState        ends
00002250
00000000 ; ---------------------------------------------------------------------------
00000000
00000000 crypto_status   struc ; (sizeof=0x1818, align=0x8, copyof_4600)
00000000                                         ; XREF: QwbState/r
00000000 statu           dq ?
00000008 crypt_key       db 2048 dup(?)
00000808 input_buf       db 2048 dup(?)
00001008 output_buf      db 2048 dup(?)
00001808 encrypt_function dq ?                   ; offset
00001810 decrypt_function dq ?                   ; offset
00001818 crypto_status   ends
```

## Vulnerability

1.Out-of-bound read in `qwb_mmio_read` caused by using strlen to do size checking for output_buf.

```C
else
{
  v18 = strlen(opaque->crypto.output_buf);
  v19 = v17 == 1;
  v20 = v17 == 1;
  if ( addr < v18 + 0x3000 && v19 )
  {
    qemu_mutex_lock_func(
      &opaque->crypto_statu_mutex,
      "/home/ctflag/Desktop/QWB/online/QMCT/qemu_qwb/hw/misc/qwb.c",
      367);
    if ( (opaque->crypto.statu - 6) & 0xFFFFFFFFFFFFFFFDLL )
    {
      qemu_mutex_unlock_impl(
        &opaque->crypto_buf_mutex,
        "/home/ctflag/Desktop/QWB/online/QMCT/qemu_qwb/hw/misc/qwb.c",
        375);
      qemu_mutex_unlock_impl(
        &opaque->crypto_statu_mutex,
        "/home/ctflag/Desktop/QWB/online/QMCT/qemu_qwb/hw/misc/qwb.c",
        376);
      result = -1LL;
    }
    else
    {
      qemu_mutex_unlock_impl(
        &opaque->crypto_statu_mutex,
        "/home/ctflag/Desktop/QWB/online/QMCT/qemu_qwb/hw/misc/qwb.c",
        370);
      v22 = *(opaque + addr - 0x15C0);
      qemu_mutex_unlock_impl(
        &opaque->crypto_buf_mutex,
        "/home/ctflag/Desktop/QWB/online/QMCT/qemu_qwb/hw/misc/qwb.c",
        372);
      result = v22;
    }
    return result;
  }
}
```

2.Out-of-bound write in `aes_encrypt_function`.

```C
if ( length > 0x800 || strlen(key1) != 16 || AES_set_encrypt_key(key1, 128LL, &aes) < 0 )
  return 0;
if ( length )
{
  v17 = output1;
  v18 = &input[((length - 1) & 0xFFFFFFFFFFFFFFF0LL) + 16];
  do
  {
    v19 = v17;
    v20 = input1;
    input1 += 16;
    v17 += 16;
    AES_ecb_encrypt(v20, v19, &aes, 1LL);
  }
  while ( v18 != input1 );
  *v27 = 0LL;
  v28 = 0;
  sum = 0;
  for ( i = 0LL; ; sum = v27[i & 7] )
  {
    v23 = output1[i] ^ sum;
    v24 = i++;
    v27[v24 & 7] = v23;
    if ( i == length )
      break;
  }
  v25 = *v27;
}
```

## Exploitation

1. Fill up output_buf and leak encrypt_function by reading output_buf[0x800]. Now we get the base address of QEMU.
2. Rewrite encrypt_function with `system@plt` via out-of-bound write in `aes_encrypt_function` to get shell.
