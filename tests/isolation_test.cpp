// Linux kernel behaviour on which the Maât same-UID hardening depends.
// This does not prove safety during execve(): Linux resets dumpability there.
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>

static void ck(bool ok,const char* what) {
    if(!ok) { std::fprintf(stderr,"FAIL: %s (errno=%d: %s)\n",what,errno,std::strerror(errno));std::exit(1); }
}
static void byte(int fd,char expected) {
    char result=0;
    ck(read(fd,&result,1)==1 && result==expected,"synchronization read");
}
static bool visible(pid_t pid) {
    char path[80],result[128];
    std::snprintf(path,sizeof(path),"/proc/%ld/fd/3",long(pid));
    return readlink(path,result,sizeof(result))>=0;
}
static bool probe(pid_t victim,uid_t uid,gid_t gid,bool expected) {
    pid_t attacker=fork();ck(attacker>=0,"fork attacker");
    if(attacker==0) {
        if(setgid(gid)!=0 || setuid(uid)!=0) _exit(10);
        bool saw=visible(victim);
        _exit(saw==expected ? 0 : 11);
    }
    int status=0;ck(waitpid(attacker,&status,0)==attacker,"wait attacker");
    return WIFEXITED(status) && WEXITSTATUS(status)==0;
}
int main() {
    ck(geteuid()==0,"requires disposable root test environment");
    // Use the unprivileged nobody identity, not the account used for SSH.
    const uid_t uid=65534;const gid_t gid=65534;
    int sync[2];ck(socketpair(AF_UNIX,SOCK_STREAM,0,sync)==0,"sync socketpair");
    pid_t victim=fork();ck(victim>=0,"fork victim");
    if(victim==0) {
        close(sync[0]);
        int c[2];if(socketpair(AF_UNIX,SOCK_SEQPACKET,0,c)!=0)_exit(11);
        if(dup2(c[0],3)!=3)_exit(12);
        if(c[0]!=3)close(c[0]);
        close(c[1]);
        if(setgid(gid)!=0 || setuid(uid)!=0)_exit(13);
        // Explicitly allow process inspection to establish a positive
        // control; changing UID can otherwise reset the dumpable bit.
        if(prctl(PR_SET_DUMPABLE,1,0,0,0)!=0)_exit(14);
        char ready='A';if(write(sync[1],&ready,1)!=1)_exit(15);
        char command=0;if(read(sync[1],&command,1)!=1||command!='P')_exit(16);
        if(prctl(PR_SET_DUMPABLE,0,0,0,0)!=0)_exit(17);
        ready='B';if(write(sync[1],&ready,1)!=1)_exit(18);
        if(read(sync[1],&command,1)!=1||command!='X')_exit(19);
        _exit(0);
    }
    close(sync[1]);byte(sync[0],'A');
    ck(probe(victim,uid,gid,true),"positive control: same-UID procfs descriptor is exposed");
    ck(write(sync[0],"P",1)==1,"request nondumpable");byte(sync[0],'B');
    ck(probe(victim,uid,gid,false),"same-UID procfs descriptor must be denied after prctl");
    ck(write(sync[0],"X",1)==1,"terminate victim");
    int status=0;ck(waitpid(victim,&status,0)==victim,"wait victim");
    ck(WIFEXITED(status) && WEXITSTATUS(status)==0,"victim exit status");
    close(sync[0]);
    std::puts("PASS same-UID /proc fd exposure controlled by PR_SET_DUMPABLE");
}
