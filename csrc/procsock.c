// Enumerates the TCP/UDP sockets of every process we are allowed to inspect, using libproc.
// Compiled against the SDK headers so struct layouts always match the running OS.

#include <libproc.h>
#include <sys/proc_info.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int32_t pid;
    int32_t proto;     // IPPROTO_TCP or IPPROTO_UDP
    int32_t v6;        // 1 if addresses are IPv6
    uint8_t laddr[16];
    uint8_t raddr[16];
    uint16_t lport;
    uint16_t rport;
} ns_sock;

typedef struct {
    int32_t pid;
    char name[64];
    char path[1024];
} ns_proc;

// Fills `socks` (up to max_socks) and `procs` (up to max_procs, one per process that owns at
// least one socket). Returns the number of sockets, writes the number of processes to *n_procs.
int ns_list_sockets(ns_sock *socks, int max_socks, ns_proc *procs, int max_procs, int *n_procs) {
    int n = 0, np = 0;
    int cap = proc_listallpids(NULL, 0);
    if (cap <= 0) {
        *n_procs = 0;
        return -1;
    }
    cap += 64;
    pid_t *pids = calloc((size_t)cap, sizeof(pid_t));
    int npids = proc_listallpids(pids, cap * (int)sizeof(pid_t));
    for (int i = 0; i < npids && n < max_socks; i++) {
        pid_t pid = pids[i];
        int size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (size <= 0) continue; // not permitted, or exited
        struct proc_fdinfo *fds = malloc((size_t)size);
        size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, size);
        int nfds = size / (int)sizeof(struct proc_fdinfo);
        int owned = 0;
        for (int j = 0; j < nfds && n < max_socks; j++) {
            if (fds[j].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
            struct socket_fdinfo si;
            if (proc_pidfdinfo(pid, fds[j].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof si) != sizeof si) continue;
            int fam = si.psi.soi_family;
            if (fam != AF_INET && fam != AF_INET6) continue;
            struct in_sockinfo *in;
            if (si.psi.soi_kind == SOCKINFO_TCP) in = &si.psi.soi_proto.pri_tcp.tcpsi_ini;
            else if (si.psi.soi_kind == SOCKINFO_IN) in = &si.psi.soi_proto.pri_in;
            else continue;
            ns_sock *s = &socks[n++];
            memset(s, 0, sizeof *s);
            s->pid = pid;
            s->proto = si.psi.soi_protocol;
            s->lport = ntohs((uint16_t)in->insi_lport);
            s->rport = ntohs((uint16_t)in->insi_fport);
            if (in->insi_vflag & INI_IPV4) {
                memcpy(s->laddr, &in->insi_laddr.ina_46.i46a_addr4, 4);
                memcpy(s->raddr, &in->insi_faddr.ina_46.i46a_addr4, 4);
            } else {
                s->v6 = 1;
                memcpy(s->laddr, &in->insi_laddr.ina_6, 16);
                memcpy(s->raddr, &in->insi_faddr.ina_6, 16);
            }
            owned = 1;
        }
        free(fds);
        if (owned && np < max_procs) {
            ns_proc *p = &procs[np++];
            memset(p, 0, sizeof *p);
            p->pid = pid;
            proc_name(pid, p->name, sizeof p->name);
            proc_pidpath(pid, p->path, sizeof p->path);
        }
    }
    free(pids);
    *n_procs = np;
    return n;
}
