#!/usr/bin/python3
#
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from bcc import libbcc, table
import pyroute2, time, sys, ctypes, socket, ipaddress, argparse, os

c_text = """
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

//in network order
BPF_HASH(sip_filter, u32, u32, HT_MAX);

BPF_ARRAY(mod_total, uint64_t, 1);
BPF_ARRAY(en_sip_filter, u32, 1);

static inline int is_en_sip_filter(void)
{
    uint32_t *en_flag;

    en_flag = en_sip_filter.lookup((uint32_t []) {0});

    if (en_flag)
    {
        return (*en_flag != 0);
    }

    return 0;
}

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

        if (is_en_sip_filter()) {
            ip = data + nh_off;

            if ((void*)&ip[1] > data_end)
                return rc;

            // truncate packets only if sip is configured in sip_filter
            {
                uint32_t *count;

                count = sip_filter.lookup(&ip->saddr);

                if (! count) {
#ifdef ENABLE_DBG
                    bpf_trace_printk("pass sip - %lx\\n", ip->saddr);
#endif
                    return XDP_PASS;
                }
            }
        }

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

dbg_path       = '/sys/fs/bpf/dbg_' + os.path.basename(os.path.splitext(__file__)[0])
flags          = 0
offload_device = None
mode           = BPF.XDP
max_filter_sips= 1024

class PinnedTable(table.HashTable):
    def __init__(self, map_path, keytype, leaftype, max_entries):
        map_fd = libbcc.lib.bpf_obj_get(ctypes.c_char_p(map_path.encode('utf-8')))
        if map_fd < 0:
            raise ValueError("Failed to open eBPF map")

        self.map_fd = map_fd
        self.Key = keytype
        self.Leaf = leaftype
        self.max_entries = max_entries

def set_filter_hosts(kpath, add_lst, del_lst):
    try:
        sip_tbl = PinnedTable(kpath, ctypes.c_uint32, ctypes.c_uint32, max_filter_sips)

        if del_lst != None:
            for sip in del_lst:
                try:
                    sip_tbl.pop(ctypes.c_uint32(socket.htonl(int(ipaddress.IPv4Address(sip)))))
                except:
                    pass

        if add_lst != None:
            for sip in add_lst:
                sip_tbl[ctypes.c_uint32(socket.htonl(int(ipaddress.IPv4Address(sip))))] = \
                    ctypes.c_uint32(1)

    except:
        print("Failed to configure SIP filter !!!")

    else:
        print("Configured SIP filter list:")
        is_none = True
        for sip in sip_tbl.keys():
            is_none = False
            print("\t{}".format(str(ipaddress.ip_address(socket.ntohl(sip.value)))))
        if is_none:
            print("\tNone")
        print("")

parser = argparse.ArgumentParser(description='Used to truncate the mirrored packets.')
parser.add_argument('--hosts', dest='HOSTS', nargs='+',
                    help='source ip addresses to filter')
parser.add_argument('--no-hosts', dest='NHOSTS', nargs='+',
                    help='remove source ip addresses configured')
parser.add_argument('-l', '--list', dest='LIST', default=None, action="store_true",
                    help='list source ip addresses configured')
parser.add_argument('-d', '--dbg', dest='DBG', action="store_true",
                    help='enable debug message')
parser.add_argument('dev', nargs ='?',
                    help='device (required if not used to toggle bpf debug message)')
args = parser.parse_args()

if max_filter_sips > 0:
    if args.HOSTS == None and args.NHOSTS == None and args.LIST == None:
        if args.dev == None:
            print("error: the following arguments are required: dev")
            exit (1)
        else:
            device = args.dev
    else:
        set_filter_hosts(dbg_path, args.HOSTS, args.NHOSTS)
        exit(0)

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
        "-DHT_MAX=%d" % max_filter_sips],
        device=offload_device, debug=[0, 0x18][args.DBG])

fn = b.load_func("xdp_reset_packet", mode, offload_device)
en_sip_filter = b.get_table("en_sip_filter")
en_sip_filter[ctypes.c_uint32(0)] = ctypes.c_uint32(0)

if max_filter_sips > 0:
    sip_filter = b.get_table("sip_filter")

    try:
        if os.path.exists(dbg_path):
            os.remove(dbg_path)

        ret = libbcc.lib.bpf_obj_pin(sip_filter.map_fd, ctypes.c_char_p(dbg_path.encode('utf-8')))
        if ret != 0:
            raise Exception("Failed to pin map !!!")

    except:
        if args.DBG == 0:
            print("SIP filter table in kernel can not be modified !!!")
            print("Plz execute \"mount -t bpf none /sys/fs/bpf\" first !!!\n")
    else:
        en_sip_filter[ctypes.c_uint32(0)] = ctypes.c_uint32(1)


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
