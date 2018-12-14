/*************************************************************************
	> File Name: enc_sock.h
	> Author: 
	> Mail: 
	> Created Time: Thu 03 May 2018 10:40:10 AM CST
 ************************************************************************/

#ifndef _ENC_SOCK_H
#define _ENC_SOCK_H

#define P_BITLEN 1024
#define P "ab1b141539b31ec6468724ad0c42d177e72f17649cfc4677ca415cfeacd792e3a32c9e4f3f9c5fc0bb95fa651b4edbbe484929d8c9991bf2b00019b4e53d26bf321c6a5b4b9efe010300a696a812869f87f4d4d1ac074b505137ac0c2e0567395d7dde02f517a7cfff8021049ba5733b974e87b459b054199c6ae600414539b7"
#define G "f"

typedef unsigned char uc;

void init_dh();

void init_rc4();

void zero_send(void *, size_t);

void zero_recv(void *, size_t);

#endif
