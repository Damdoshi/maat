/* SPDX-License-Identifier: MIT: Apache -> broker identity verification using
 * kernel connection descriptors passed via SCM_RIGHTS, never HTTP data. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "maat_broker_client.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

static size_t field(unsigned char *out,const char *value) {
    size_t n=strlen(value);
    out[0]=(unsigned char)(n>>24);out[1]=(unsigned char)(n>>16);
    out[2]=(unsigned char)(n>>8);out[3]=(unsigned char)n;
    memcpy(out+4,value,n);return 4+n;
}
static int read_field(const unsigned char *src,size_t n,size_t *offset,
                      const unsigned char **bytes,size_t *length,size_t maximum) {
    uint32_t size;
    if(*offset>n || n-*offset<4) return 0;
    size=((uint32_t)src[*offset]<<24)|((uint32_t)src[*offset+1]<<16)|
         ((uint32_t)src[*offset+2]<<8)|src[*offset+3];
    *offset+=4;
    if(size>maximum || size>n-*offset) return 0;
    *bytes=src+*offset;*length=size;*offset+=size;return 1;
}
int maat_broker_verify_fd(int broker_fd,uid_t expected_broker_uid,
                          int accepted_tcp_fd,struct maat_verified_identity *identity) {
    static const unsigned char prefix[19]={0,0,0,11,'s','s','h','-','e','d','2','5','5','1','9',0,0,0,32};
    struct ucred credentials;
    socklen_t clen=sizeof(credentials);
    unsigned char message[64],answer[512];
    union {struct cmsghdr hdr;char bytes[CMSG_SPACE(sizeof(int))];} ancillary;
    struct iovec iov;
    struct msghdr msg;
    struct cmsghdr *c;
    const unsigned char *magic,*user,*key;
    size_t offset=0,mn=0,un=0,kn=0,i;
    ssize_t received;
    if(identity==NULL || accepted_tcp_fd<0) return 0;
    memset(identity,0,sizeof(*identity));
    if(getsockopt(broker_fd,SOL_SOCKET,SO_PEERCRED,&credentials,&clen)!=0 ||
       clen!=sizeof(credentials) || credentials.uid!=expected_broker_uid) return 0;
    offset=field(message,"MAATLOOKUP2");
    memset(message+offset,0,4);offset+=4;
    memset(&ancillary,0,sizeof(ancillary));memset(&msg,0,sizeof(msg));
    iov.iov_base=message;iov.iov_len=offset;
    msg.msg_iov=&iov;msg.msg_iovlen=1;
    msg.msg_control=ancillary.bytes;msg.msg_controllen=sizeof(ancillary.bytes);
    c=CMSG_FIRSTHDR(&msg);
    c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_RIGHTS;
    c->cmsg_len=CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(c),&accepted_tcp_fd,sizeof(int));
    if(sendmsg(broker_fd,&msg,MSG_NOSIGNAL)!=(ssize_t)offset) return 0;
    received=recv(broker_fd,answer,sizeof(answer),MSG_TRUNC);
    if(received<=0 || received>(ssize_t)sizeof(answer)) return 0;
    offset=0;
    if(!read_field(answer,(size_t)received,&offset,&magic,&mn,20) || mn!=10 ||
       memcmp(magic,"MAATIDENT2",10)!=0 ||
       !read_field(answer,(size_t)received,&offset,&user,&un,MAAT_MAX_SSH_USER) ||
       !read_field(answer,(size_t)received,&offset,&key,&kn,MAAT_KEY_BYTES) ||
       offset!=(size_t)received || un==0 || kn!=MAAT_KEY_BYTES ||
       memcmp(key,prefix,19)!=0) return 0;
    for(i=0;i<un;++i) if(user[i]<0x20 || user[i]>0x7e) return 0;
    memcpy(identity->ssh_user,user,un);
    memcpy(identity->public_key,key,kn);
    return 1;
}
int maat_broker_verify(const char *socket_path,uid_t expected_broker_uid,
                       int accepted_tcp_fd,struct maat_verified_identity *identity) {
    struct sockaddr_un address;
    struct stat st;
    char directory[sizeof(address.sun_path)];
    const char *slash;
    size_t n;
    struct timeval timeout={2,0};
    int fd,valid;
    if(identity==NULL) return 0;
    memset(identity,0,sizeof(*identity));
    if(socket_path==NULL || strlen(socket_path)>=sizeof(address.sun_path)) return 0;
    slash=strrchr(socket_path,'/');
    if(slash==NULL || slash==socket_path) return 0;
    n=(size_t)(slash-socket_path);
    if(n>=sizeof(directory)) return 0;
    memcpy(directory,socket_path,n);directory[n]='\0';
    if(lstat(directory,&st)!=0 || !S_ISDIR(st.st_mode) || st.st_uid!=0 ||
       (st.st_mode&(S_IWGRP|S_IWOTH))!=0) return 0;
    if(lstat(socket_path,&st)!=0 || !S_ISSOCK(st.st_mode) ||
       st.st_uid!=geteuid() || (st.st_mode&0077)!=0) return 0;
    fd=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    if(fd<0) return 0;
    (void)setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    (void)setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    memset(&address,0,sizeof(address));address.sun_family=AF_UNIX;
    memcpy(address.sun_path,socket_path,strlen(socket_path)+1);
    valid=connect(fd,(struct sockaddr*)&address,sizeof(address))==0 &&
          maat_broker_verify_fd(fd,expected_broker_uid,accepted_tcp_fd,identity);
    close(fd);return valid;
}
