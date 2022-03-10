#!/usr/bin/python3
#
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2, time, sys, ctypes, socket, ipaddress, argparse

c_text = """
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#if HT_MAX > 0
//in network order
BPF_HASH(sip_hash, u32, u32, HT_MAX);
#endif

BPF_ARRAY(mod_total, uint64_t, 1);

static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
    struct iphdr *iph = data + nh_off;

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

static inline u16 ipv4_len(void *data, u64 nh_off, void *data_end) {
     struct iphdr *iph = data + nh_off;
     return iph->ihl*4;
}

static inline u16 ipv4_totallen(void *data, u64 nh_off, void *data_end) {
     struct iphdr *iph = data + nh_off;
     return iph->tot_len;
}

static inline int parse_ipv6(void *data, u64 nh_off, void *data_end) {
    struct ipv6hdr *ip6h = data + nh_off;

    if ((void*)&ip6h[1] > data_end)
        return 0;
    return ip6h->nexthdr;
}

static inline unsigned short checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

static inline void update_mod_c (void) {
    uint64_t *mod_c;

    mod_c = mod_total.lookup((uint32_t []) {0});
    if (mod_c) {
        *mod_c += 1;
    }
    else {
        mod_total.update( (uint32_t []) {0}, (uint64_t []) {1} );
    }
}

int xdp_reset_packet(struct CTXTYPE *ctx) {

    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    void* payload;
    struct ethhdr *eth = data;
    struct iphdr *ip;

    // drop packets
    int rc = XDP_PASS; /*RETURNCODE;*/ // let pass XDP_PASS or redirect to tx via XDP_TX
    long *value;
    uint16_t h_proto;
    uint64_t nh_off = 0;
    uint32_t index;
    uint16_t ip_hlength, ip_totallen;
    int32_t reset_len;

    nh_off = sizeof(*eth);

    if (data + nh_off  > data_end)
        return rc;

    h_proto = eth->h_proto;

    // parse double vlans
    #pragma unroll
    for (int i=0; i<2; i++) {
        if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
            struct vlan_hdr *vhdr;

            vhdr = data + nh_off;
            nh_off += sizeof(struct vlan_hdr);
            if (data + nh_off > data_end)
                return rc;
            h_proto = vhdr->h_vlan_encapsulated_proto;
        }
    }

    if (h_proto == htons(ETH_P_IP)) {

#if HT_MAX > 0
        ip = data + nh_off;

        if ((void*)&ip[1] > data_end)
            return rc;

        // truncate packets only if sip is configured in sip_hash
        {
            uint32_t *count;

            count = sip_hash.lookup(&ip->saddr);

            if (! count) {
#ifdef ENABLE_DBG
                bpf_trace_printk("pass sip - %lx\\n", ip->saddr);
#endif
                return XDP_PASS;
            }
        }
#endif

        index = parse_ipv4(data, nh_off, data_end);
        ip_hlength = ipv4_len(data, nh_off, data_end);
        ip_totallen = ipv4_totallen(data, nh_off, data_end);
        //reset packet
        if(index == 17) { //udp
            nh_off = nh_off + ip_hlength + sizeof(struct udphdr);
        } else if (index == 6) { //tcp
            nh_off = nh_off + ip_hlength + sizeof(struct tcphdr);
        } else {
            return XDP_PASS;
        }

        reset_len = nh_off - (data_end - data);

        bpf_xdp_adjust_tail(ctx, reset_len);

        update_mod_c();
    }
    else if (h_proto == htons(ETH_P_IPV6)) { /*we won't process ipv6 extesion header*/
        index = parse_ipv6(data, nh_off, data_end);
        if(index == 17) { //udp
            nh_off = nh_off + 40 /*ipv6 h len*/ + sizeof(struct udphdr);
        } else if (index == 6) { //tcp
            nh_off = nh_off + 40 /*ipv6 h len*/ + sizeof(struct tcphdr);
        } else {
            return XDP_PASS;
        }

        reset_len = nh_off - (data_end - data);

        bpf_xdp_adjust_tail(ctx, reset_len);

        update_mod_c();
    }
    else
        index = 0;

    return rc;
}
"""

parser = argparse.ArgumentParser(description='Used to truncate the mirrored packets.')
parser.add_argument('--hosts', dest='HOSTS', nargs='+', help='source ip addresses to filter')
parser.add_argument('-d', '--dbg', dest='DBG', action="store_true", help='enable debug message')
parser.add_argument('dev', help='device' )
args = parser.parse_args()

filter_sip = []

if args.HOSTS:
    for host in args.HOSTS:
        filter_sip.append(int(ipaddress.IPv4Address(host)))

device = args.dev
flags = 0
offload_device = None

#if len(sys.argv) == 2:
#    device = sys.argv[1]
#elif len(sys.argv) == 3:
#    device = sys.argv[2]

if len(sys.argv) == 3:
    if "-S" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= BPF.XDP_FLAGS_SKB_MODE
    if "-D" in sys.argv:
        # XDP_FLAGS_DRV_MODE
        flags |= BPF.XDP_FLAGS_DRV_MODE
    if "-H" in sys.argv:
        # XDP_FLAGS_HW_MODE
        offload_device = device
        flags |= BPF.XDP_FLAGS_HW_MODE

mode = BPF.XDP
#mode = BPF.SCHED_CLS

if mode == BPF.XDP:
    ret = "XDP_DROP"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"

# load BPF program
b = BPF(text=c_text, cflags=["-w", "-DKBUILD_MODNAME",
        "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype,
        ["", "-DENABLE_DBG"][args.DBG],
        "-DHT_MAX=%d" % len(filter_sip)],
        device=offload_device, debug=[0, 0x18][args.DBG])

fn = b.load_func("xdp_reset_packet", mode, offload_device)

if mode == BPF.XDP:
    b.attach_xdp(device, fn, flags)
else:
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent="ffff:fff2", classid=1, direct_action=True)

mod_tot = b.get_table("mod_total")

if len(filter_sip) > 0:
    sip_hash = b.get_table("sip_hash")

    # configure sip of the packet to be modified
    for tmp_ip in filter_sip:
        sip_hash[ctypes.c_uint(socket.htonl(tmp_ip))] = ctypes.c_uint(1)

print("Printing packet modification counter, hit CTRL+C to stop")
while 1:
    try:
        time.sleep(10)

        print("modify count {}".format(mod_tot[0].value))

    except KeyboardInterrupt:
        print("Removing filter from device")
        break

if mode == BPF.XDP:
    b.remove_xdp(device, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
