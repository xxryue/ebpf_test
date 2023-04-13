/**********************************************************
    > File Name: main.c
    > Author:yuemx
    > Mail:xxr_2011@outllok.com
    > Created Time: 2023年04月12日 星期三 15时30分53秒
 **********************************************************/
#include <stdio.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <net/if.h>
#include <time.h>
#include "socketfilter.skeleton.h"
#include "connect.skeleton.h"
#include <signal.h>
#include "common.h"
static const char * ipproto_mapping[IPPROTO_MAX] = {
        [IPPROTO_IP] = "IP",
        [IPPROTO_ICMP] = "ICMP",
        [IPPROTO_IGMP] = "IGMP",
        [IPPROTO_IPIP] = "IPIP",
        [IPPROTO_TCP] = "TCP",
        [IPPROTO_EGP] = "EGP",
        [IPPROTO_PUP] = "PUP",
        [IPPROTO_UDP] = "UDP",
        [IPPROTO_IDP] = "IDP",
        [IPPROTO_TP] = "TP",
        [IPPROTO_DCCP] = "DCCP",
        [IPPROTO_IPV6] = "IPV6",
        [IPPROTO_RSVP] = "RSVP",
        [IPPROTO_GRE] = "GRE",
        [IPPROTO_ESP] = "ESP",
        [IPPROTO_AH] = "AH",
        [IPPROTO_MTP] = "MTP",
        [IPPROTO_BEETPH] = "BEETPH",
        [IPPROTO_ENCAP] = "ENCAP",
        [IPPROTO_PIM] = "PIM",
        [IPPROTO_COMP] = "COMP",
        [IPPROTO_SCTP] = "SCTP",
        [IPPROTO_UDPLITE] = "UDPLITE",
        [IPPROTO_MPLS] = "MPLS",
        [IPPROTO_RAW] = "RAW"
};

static int libbpf_print_fn(enum libbpf_print_level, const char *format, va_list args){
    return vfprintf(stderr, format, args);
}

static int open_raw_sock(const char *name){
    struct sockaddr_ll sll;
    int sock;

    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0) {
        fprintf(stderr, "Failed to create raw socket\n");
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(name);
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "Failed to bind to %s: %s\n", name, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static int handle_event(void *ctx, void *data, size_t data_size){
    const struct so_event *e = data;
    char ifname[IF_NAMESIZE];
    if(e->pkt_type != PACKET_HOST)
        return 0;

    if(e->ip_proto < 0 || e->ip_proto >= IPPROTO_MAX)
        return 0;

    if(!if_indextoname(e->ifindex, ifname)){
        return 0;
    }
    printf("interface: %s\tprotocol: %s\t%s:%d(src) -> %s:%d(dst)\n",
           ifname,
           ipproto_mapping[e->ip_proto],
           inet_ntoa((struct in_addr){e->saddr}),
           ntohs(e->port16[0]),
           inet_ntoa((struct in_addr){e->daddr}),
           ntohs(e->port16[1])
    );
    return 0;
}
static volatile bool exiting = false;

static void sig_handler(int sig){
    exiting = true;
}

static int socket_filter(void){
    struct ring_buffer *rb = NULL;
    struct socketfilter_bpf *skeleton;
    int err, prog_fd, sock;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_print(libbpf_print_fn);

    skeleton = socketfilter_bpf__open_and_load();
    if(!skeleton){
        fprintf(stderr, "failed to open and load BPF skeleton\n");
        return 1;
    }
    fprintf(stderr, "load BPF skeleton succeed");

    rb = ring_buffer__new(bpf_map__fd(skeleton->maps.rb), handle_event, NULL, NULL);
    if(!rb){
        err == -1;
        fprintf(stderr, "Failed to create ringbuffer\n");
        goto cleanup;
    }
    sock = open_raw_sock("enp89s0");
    if (sock < 0) {
        err = -2;
        fprintf(stderr, "Failed to open raw socket\n");
        goto cleanup;
    }
    prog_fd = bpf_program__fd(skeleton->progs.bpf_socket_handler);
    if(setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))){
        err = -3;
        fprintf(stderr, "Failed to attach to raw socket\n");
        goto cleanup;
    }
    while (!exiting){
        err = ring_buffer__poll(rb, 100);
        if(err == -EINTR){
            err = 0;
            break;
        }
        if(err < 0){
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
        sleep(1);
    }
    return 0;

    cleanup:
    ring_buffer__free(rb);
    socketfilter_bpf__destroy(skeleton);
    return -err;
}
static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
    stop = 1;
}
static int connect_event(void *ctx, void *data, size_t data_size){
    const struct connect_event *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%h:%M:%S", tm);
    printf("pid[%d], name[%s] connect to [%s:%d]\n", e->caller_pid, e->comm,
           inet_ntoa((struct in_addr){e->daddr}),
           ntohs(e->port16[1]));
    return 0;
}
static void connect_probe(void){
    struct connect_bpf *skeleton = NULL;
    struct ring_buffer *rb = NULL;
    int err;
    libbpf_set_print(libbpf_print_fn);
    skeleton = connect_bpf__open_and_load();
    if(!skeleton){
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return;
    }
    err = connect_bpf__attach(skeleton);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    rb = ring_buffer__new(bpf_map__fd(skeleton->maps.rb_connect),
                          connect_event,NULL, NULL);
    if(!rb){
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    while (!exiting){
        err = ring_buffer__poll(rb, 100);
        if(err == -EINTR){
            err = 0;
            break;
        }
        if(err < 0){
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    connect_bpf__destroy(skeleton);
    return;
}

int main(int argc, char *argv[]){
    //connect_probe();
    socket_filter();
}
