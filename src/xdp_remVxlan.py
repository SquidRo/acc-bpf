#!/usr/bin/python3
#
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from bcc import libbcc, table
import pyroute2, time, sys, argparse, ctypes, os

c_text = """
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <bcc/proto.h>

BPF_ARRAY(dbg_opt, uint32_t, 1); // 0 off, 1 on

BPF_ARRAY(rem_total, uint64_t, 1);

#ifndef ENABLE_DBG
static inline int is_dbg_on_ex(void)
{
    uint32_t *dbg_flag;

    dbg_flag = dbg_opt.lookup((uint32_t []) {0});

    if (dbg_flag)
    {
        return (*dbg_flag != 0);
    }

    return 0;
}
#endif

static inline void update_rem_total(void)
{
    uint64_t *rem_c;

    rem_c = rem_total.lookup((uint32_t []) {0});
    if (rem_c)
    {
        *rem_c += 1;
    }
    else
    {
        rem_total.update( (uint32_t []) {0}, (uint64_t []) {1} );
    }
}

// next_proto (in network order)
// retutn len of eth header or -1 if failed
static inline int get_eth_hdr_len(
    void *data, void *data_end, u32 cur_ofs, uint16_t *next_proto)
{
    struct ethhdr   *eth;
    int             len  = sizeof(*eth);

    eth = data + cur_ofs;
    if ((void *)&eth[1] > data_end)
        return -1;

    *next_proto = eth->h_proto;

    return len;
}

// next_proto (in network order)
// retutn len of vlan header or -1 if failed
static inline int get_vlan_hdr_len(
    void *data, void *data_end, uint32_t cur_ofs, uint16_t *next_proto)
{
    struct vlan_hdr *vhdr;
    int             len = 0;

    #pragma unroll
    for (int i=0; i<2; i++)
    {
        vhdr = data + cur_ofs + len;

        if ((void *)&vhdr[1] > data_end)
        {
            return (i == 0) ? -1 : len;
        }

        *next_proto = vhdr->h_vlan_encapsulated_proto;
        len += sizeof(*vhdr);

        if (!(*next_proto == htons(ETH_P_8021Q) || *next_proto == htons(ETH_P_8021AD)))
        {
            break;
        }
    }

    return len;
}

// next_proto (in network order)
// retutn len of ip header or -1 if failed
static inline int get_ip4_hdr_len(
    void *data, void *data_end, uint32_t cur_ofs, uint16_t *next_proto)
{
    struct iphdr *iph = data + cur_ofs;

    if ((void *)&iph[1] > data_end)
        return -1;

    *next_proto = iph->protocol;

    return iph->ihl << 2;
}

// next_proto (in network order)
// retutn len of ip6 header or -1 if failed
static inline int get_ip6_hdr_len(
    void *data, void *data_end, uint32_t cur_ofs, uint16_t *next_proto)
{
    struct ipv6hdr *ip6h = data + cur_ofs;

    if ((void *)&ip6h[1] > data_end)
        return -1;

    *next_proto = ip6h->nexthdr;

    return sizeof(*ip6h);
}

// dst port (in network order)
// retutn len of udp header or -1 if failed
static inline int get_udp_hdr_len(
    void *data, void *data_end, uint32_t cur_ofs, uint16_t *dst_port)
{
    struct udphdr *udph = data + cur_ofs;

    if ((void *)&udph[1] > data_end)
        return -1;

    *dst_port = udph->dest;

    return sizeof(*udph);
}

// retutn len of vxlan header or -1 if failed
static inline int get_vxlan_hdr_len(
    void *data, void *data_end, uint32_t cur_ofs)
{
    struct vxlan_t *vxlanh = data + cur_ofs;

    if ((void *)&vxlanh[1] > data_end)
        return -1;

    return sizeof(*vxlanh);
}

int xdp_remVxlan(struct CTXTYPE *ctx)
{
    void        *data_end = (void*)(long)ctx->data_end;
    void        *data = (void*)(long)ctx->data;
    uint64_t    *rem_c;
    uint32_t    cur_ofs =0;
    uint16_t    next_proto;
    int         hdr_len;

    hdr_len = get_eth_hdr_len(data, data_end, cur_ofs, &next_proto);
    if (hdr_len > 0)
    {
        cur_ofs += hdr_len;

        if (next_proto == htons(ETH_P_8021Q) || next_proto == htons(ETH_P_8021AD))
        {
            hdr_len = get_vlan_hdr_len(data, data_end, cur_ofs, &next_proto);

            if (hdr_len < 0)
                return XDP_PASS;

            cur_ofs += hdr_len;

#ifndef ENABLE_DBG
            if (is_dbg_on_ex())
#endif
            {
                bpf_trace_printk("vlan ofs - %d" DBGLR, cur_ofs);
            }
        }

        switch (next_proto)
        {
        case htons(ETH_P_IP):
            hdr_len = get_ip4_hdr_len(data, data_end, cur_ofs, &next_proto);

            if (hdr_len < 0)
                return XDP_PASS;

            cur_ofs += hdr_len;

#ifndef ENABLE_DBG
            if (is_dbg_on_ex())
#endif
            {
                bpf_trace_printk("ip ofs - %d" DBGLR, cur_ofs);
            }

            break;

        case htons(ETH_P_IPV6):
            //TODO: skip all ext header ???
            hdr_len = get_ip6_hdr_len(data, data_end, cur_ofs, &next_proto);

            if (hdr_len < 0)
                return XDP_PASS;

            cur_ofs += hdr_len;

#ifndef ENABLE_DBG
            if (is_dbg_on_ex())
#endif
            {
                bpf_trace_printk("ip6 ofs - %d" DBGLR, cur_ofs);
            }

            break;

        default:
            return XDP_PASS;
        }

        switch (next_proto)
        {
        case IPPROTO_UDP:
            hdr_len = get_udp_hdr_len(data, data_end, cur_ofs, &next_proto);

            if (hdr_len < 0)
                return XDP_PASS;

            cur_ofs += hdr_len;

#ifndef ENABLE_DBG
            if (is_dbg_on_ex())
#endif
            {
                bpf_trace_printk("udp ofs - %d" DBGLR, cur_ofs);
            }
            break;

        default:
            return XDP_PASS;
        }

        if (next_proto == htons(4789))
        {
            void *data_end = (void*)(long)ctx->data_end; // make verifier happy
            void *data = (void*)(long)ctx->data;

            hdr_len = get_vxlan_hdr_len(data, data_end, cur_ofs);

            if (hdr_len < 0)
                return XDP_PASS;

            cur_ofs += hdr_len;

#ifndef ENABLE_DBG
            if (is_dbg_on_ex())
#endif
            {
                bpf_trace_printk("vxlan ofs - %d" DBGLR, cur_ofs);
            }

            bpf_xdp_adjust_head(ctx, cur_ofs);

            update_rem_total();
        }
    }

    return XDP_PASS;
}
"""

dbg_path        = '/sys/fs/bpf/dbg_remvxlan'
flags           = 0
offload_device  = None
mode            = BPF.XDP

class PinnedArray(table.Array):
    def __init__(self, map_path, keytype, leaftype, max_entries):
        map_fd = libbcc.lib.bpf_obj_get(ctypes.c_char_p(map_path.encode('utf-8')))
        if map_fd < 0:
            raise ValueError("Failed to open eBPF map")

        self.map_fd = map_fd
        self.Key = keytype
        self.Leaf = leaftype
        self.max_entries = max_entries

parser = argparse.ArgumentParser(
            description='Used to remove the vxlan header of mirrored packets.')

parser.add_argument('-d', '--dbg', dest='DBG', type=int, default=0,
                    help='debug flag for bcc')
parser.add_argument('--kdbg', dest='KDBG', action='store_const', const=True,
                    help='enable bpf debug message')
parser.add_argument('--no-kdbg', dest='KDBG', action='store_const', const=False,
                    help='disable bpf debug message')
parser.add_argument('dev', nargs ='?',
                    help='device (required if not used to toggle bpf debug message)')

args = parser.parse_args()

if args.KDBG == None:
    if args.dev == None:
        print("error: the following arguments are required: dev")
        exit (1)
    else:
        device = args.dev

else:
    try:
        kdbg    = PinnedArray(dbg_path, ctypes.c_uint32, ctypes.c_uint32, 1)
        kdbg[0] = ctypes.c_uint32([0, 1][args.KDBG])

    except:
        print("Failed to toggle bpf debug flag !!!")

    else:
        print("BPF debug flag is {}.".format(["disabled", "enabled"][args.KDBG]))

    finally:
        exit(0)


if mode == BPF.XDP:
    ret = "XDP_DROP"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"

# load BPF program
b = BPF(text=c_text, cflags=["-c", "-w", "-DKBUILD_MODNAME",
        ["", "-DENABLE_DBG"] [args.DBG != 0],
        '-DDBGLR="\\n"',
        "-DCTXTYPE=%s" % ctxtype ],
        device=offload_device, debug=args.DBG)

fn = b.load_func("xdp_remVxlan", mode, offload_device)

dbg_opt = b.get_table("dbg_opt")

try:
    if os.path.exists(dbg_path):
        os.remove(dbg_path)

    ret = libbcc.lib.bpf_obj_pin(dbg_opt.map_fd, ctypes.c_char_p(dbg_path.encode('utf-8')))
    if ret != 0:
        raise Exception("Failed to pin map !!!")

except:
    if args.DBG == 0:
        print("Debug flag in kernel can not be modified !!!")
        print("Plz execute \"mount -t bpf none /sys/fs/bpf\" first !!!\n")

if mode == BPF.XDP:
    b.attach_xdp(device, fn, flags)
else:
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent="ffff:fff2", classid=1, direct_action=True)

rem_total = b.get_table("rem_total")
sleep_sec = 10  # in seconds

if args.DBG != 0:
    print("Printing debug info,", end= " ")

print("hit CTRL+C to stop")

i = 0

while 1:
    try:
        time.sleep(sleep_sec)

        i += 1

        print ("rem_total/pps : {}/{})".format(
            rem_total[0].value, rem_total[0].value/(i*sleep_sec)))

    except KeyboardInterrupt:
        print("Removing filter from device")
        break

if mode == BPF.XDP:
    b.remove_xdp(device, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
