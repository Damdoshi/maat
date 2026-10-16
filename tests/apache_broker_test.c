/* Unit wire test: Apache forwards an accepted descriptor to the root broker.
 * No request header, ticket or user-controlled identity field is involved. */
#define _GNU_SOURCE
#include "../modules/mod_maat/maat_broker_client.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define CHECK(p) do {if (!(p)) {fprintf(stderr,"FAIL %s at line %d\n",#p,__LINE__);exit(1);}}while(0)
static size_t put(unsigned char *p,const void *content,size_t n) {
    p[0]=(unsigned char)(n>>24);p[1]=(unsigned char)(n>>16);
    p[2]=(unsigned char)(n>>8);p[3]=(unsigned char)n;
    memcpy(p+4,content,n);return 4+n;
}
static void scenario(int mode,uid_t expected,int success) {
    int fds[2],stream[2];unsigned char buf[512];size_t off=0;
    unsigned char key[51]={0};struct maat_verified_identity result;
    CHECK(socketpair(AF_UNIX,SOCK_SEQPACKET,0,fds)==0);
    CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,stream)==0);
    key[3]=11;memcpy(key+4,"ssh-ed25519",11);key[18]=32;
    for(int i=19;i<51;++i)key[i]=(unsigned char)i;
    off+=put(buf+off,"MAATIDENT2",10);
    if(mode==1)buf[5]='?';
    off+=put(buf+off,"alice",5);
    if(mode==2)buf[off-1]=0;
    off+=put(buf+off,key,sizeof(key));
    if(mode==3)buf[off-51+5]=0;
    if(mode==4)buf[off++]='X';
    if(mode==5)off=6;
    CHECK(send(fds[1],buf,off,0)==(ssize_t)off);
    CHECK(maat_broker_verify_fd(fds[0],expected,stream[0],&result)==success);
    if(success) {
        CHECK(strcmp(result.ssh_user,"alice")==0);
        CHECK(memcmp(key,result.public_key,51)==0);
    }else CHECK(result.ssh_user[0]==0);
    if(expected==geteuid()) {
        unsigned char request[100];union {struct cmsghdr c;char bytes[CMSG_SPACE(sizeof(int)*2)];} ancillary;
        struct iovec io={request,sizeof(request)};struct msghdr msg={0};
        msg.msg_iov=&io;msg.msg_iovlen=1;msg.msg_control=ancillary.bytes;
        msg.msg_controllen=sizeof(ancillary.bytes);
        ssize_t n=recvmsg(fds[1],&msg,MSG_DONTWAIT);
        CHECK(n==19); CHECK(memcmp(request+4,"MAATLOOKUP2",11)==0);
        struct cmsghdr *c=CMSG_FIRSTHDR(&msg);CHECK(c!=NULL);
        CHECK(c->cmsg_level==SOL_SOCKET && c->cmsg_type==SCM_RIGHTS);
        int received=-1;memcpy(&received,CMSG_DATA(c),sizeof(received));CHECK(received>=0);
        close(received);
    }
    close(fds[0]);close(fds[1]);close(stream[0]);close(stream[1]);
}
int main(void) {
    for(int i=0;i<6;++i) scenario(i,geteuid(),i==0);
    scenario(0,geteuid()+1,0);
    puts("PASS Apache broker: descriptor IPC, source UID, malformed payload, no identity leakage");
}
