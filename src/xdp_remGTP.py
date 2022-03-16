#!/usr/bin/python3
#
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2, time, sys, argparse

c_text = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/gtp.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/gtp.h>
#include <bcc/proto.h>

// only for GTPv1-U
BPF_ARRAY(rem_total, uint64_t, 1);

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
    struct ethhdr   *eth = data + cur_ofs;
    int             len  = sizeof(*eth);

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

// dst port (in network order)
// retutn len of tcp header or -1 if failed
static inline int get_tcp_hdr_len(
    void *data, void *data_end, uint32_t cur_ofs, uint16_t *dst_port)
{
    struct tcphdr *tcph = data + cur_ofs;

    if ((void *)&tcph->dest> data_end) // make verifier happy
        return -1;

    *dst_port = tcph->dest;

    if ((void *)&tcph[1]> data_end)
        return -1;

    return tcph->doff << 2;
}

// retutn len of gtp1u header or -1 if failed
static inline int get_gtp1u_hdr_len(
    void *data, void *data_end, uint32_t cur_ofs)
{
    //refer to gtp1u_udp_encap_recv in linux kernel
    struct gtp1_header  *gtp1h = data + cur_ofs;
    int                 hdr_len = sizeof(*gtp1h);

    if ((void *)&gtp1h[1] > data_end)
        return -1;

    if ((gtp1h->flags >> 5) != GTP_V1)
        return -1;

    if (gtp1h->type != GTP_TPDU)
        return -1;

    if (gtp1h->flags & GTP1_F_MASK)
        hdr_len += 4;

    return hdr_len;
}

// return 1 if ipv4 header exists at the specified offset
static inline int is_ip4_hdr(
    void *data, void *data_end, uint32_t cur_ofs)
{
    struct iphdr *iph = data + cur_ofs;

    if ((void *)&iph[1] > data_end)
        return -1;

    return (iph->version == 4);
}

int xdp_remGTP(struct CTXTYPE *ctx)
{
    void        *data_end = (void*)(long)ctx->data_end;
    void        *data = (void*)(long)ctx->data;
    uint64_t    *rem_c;
    uint32_t    cur_ofs =0;
    int         hdr_len;
                // for eth/vlan/ip/udp or tcp/gprs/
                //       0/   1/ 2/         3/   4/
    int         hdr_len_rec[5] = {0};
    int         is_outer_ip4 = 0;
    int         is_inner_ip4 = 0;
    uint16_t    next_proto;

    hdr_len = get_eth_hdr_len(data, data_end, cur_ofs, &next_proto);
    if (hdr_len > 0)
    {
        cur_ofs += hdr_len;
        hdr_len_rec[0] = hdr_len;

        if (next_proto == htons(ETH_P_8021Q) || next_proto == htons(ETH_P_8021AD))
        {
            hdr_len = get_vlan_hdr_len(data, data_end, cur_ofs, &next_proto);

            if (hdr_len < 0)
                return XDP_PASS;

            cur_ofs += hdr_len;
            hdr_len_rec[1] = hdr_len;

#ifdef ENABLE_DBG
            bpf_trace_printk("vlan ofs - %d" DBG_LR, cur_ofs);
#endif
        }

        switch (next_proto)
        {
        case htons(ETH_P_IP):
            hdr_len = get_ip4_hdr_len(data, data_end, cur_ofs, &next_proto);

            if (hdr_len < 0)
                return XDP_PASS;

            cur_ofs += hdr_len;
            hdr_len_rec[2] = hdr_len;

#ifdef ENABLE_DBG
            bpf_trace_printk("ip ofs - %d" DBG_LR, cur_ofs);
#endif

            is_outer_ip4 = 1;
            break;

        case htons(ETH_P_IPV6):
            //TODO: skip all ext header ???
            hdr_len = get_ip6_hdr_len(data, data_end, cur_ofs, &next_proto);

            if (hdr_len < 0)
                return XDP_PASS;

            cur_ofs += hdr_len;
            hdr_len_rec[2] = hdr_len;

#ifdef ENABLE_DBG
            bpf_trace_printk("ip6 ofs - %d" DBG_LR, cur_ofs);
#endif

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
            hdr_len_rec[3] = hdr_len;

#ifdef ENABLE_DBG
            bpf_trace_printk("udp ofs - %d" DBG_LR, cur_ofs);
#endif
            break;

        case IPPROTO_TCP:
            hdr_len = get_tcp_hdr_len(data, data_end, cur_ofs, &next_proto);

            if (hdr_len < 0)
                return XDP_PASS;

            cur_ofs += hdr_len;
            hdr_len_rec[3] = hdr_len;

#ifdef ENABLE_DBG
            bpf_trace_printk("tcp ofs - %d" DBG_LR, cur_ofs);
#endif
            break;

        default:
            return XDP_PASS;
        }

        if (next_proto == htons(GTP1U_PORT))
        {
            int cut_len, l2_hdr_len;

            hdr_len = get_gtp1u_hdr_len(data, data_end, cur_ofs);

            if (hdr_len < 0)
                return XDP_PASS;

            cur_ofs += hdr_len;

#ifdef ENABLE_DBG
            bpf_trace_printk("gtp1u ofs - %d" DBG_LR, cur_ofs);
#endif

            hdr_len_rec[4] = hdr_len;

            is_inner_ip4 = is_ip4_hdr(data, data_end, cur_ofs);

            // need to cut inserted (ip/udp or tcp /gprs) part
            //    cut_len max: 60 + 60 + 12
            // l2_hdr_len max: 14 + 8
            cut_len    = hdr_len_rec[2] + hdr_len_rec[3] + hdr_len_rec[4];
            l2_hdr_len = hdr_len_rec[0] + hdr_len_rec[1];

            if (is_inner_ip4 != is_outer_ip4)
            {
                // need to modify the ethertype
                l2_hdr_len -= 2;
            }

            // move eth + vlan headear forward to strip the gtp tunnel header
            for (int i=0; i<l2_hdr_len; i++)
            {
                char *src, *dst;

                src = data + i;
                if (&src[1] > data_end)
                    return XDP_PASS;

                dst = data + i + (cut_len & 0xff); // make verifier happy
                if (&dst[1] > data_end)
                    return XDP_PASS;

                *dst = *src;
            }

            if (is_inner_ip4 != is_outer_ip4)
            {
                char *dst;

                // need to modify the ethertype
                dst = data + (l2_hdr_len & 0xff) + (cut_len & 0xff); // make verifier happy
                if (&dst[2] > data_end)
                    return XDP_PASS;

                if (!is_inner_ip4)
                {
                    dst[0] = 0x86;
                    dst[1] = 0xdd;
                }
                else
                {
                   dst[0] = 0x08;
                   dst[1] = 0x00;
                }
            }

            bpf_xdp_adjust_head(ctx, cut_len);

            update_rem_total();
        }
    }

    return XDP_PASS;
}
"""

parser = argparse.ArgumentParser(description=
            'Used to remove the GTPv1-U tunnel header of mirrored packets.')
parser.add_argument('-d', '--dbg', dest='DBG', type=int, default=0, help='debug flag for bcc' )
parser.add_argument('dev', help='device' )
args = parser.parse_args()

flags = 0
offload_device = None
device = args.dev
mode = BPF.XDP

if mode == BPF.XDP:
    ret = "XDP_DROP"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"

# load BPF program
b = BPF(text=c_text, cflags=["-c", "-w", "-DKBUILD_MODNAME",
        ["", "-DENABLE_DBG"] [args.DBG != 0],
        '-DDBG_LR="\\n"',
        "-DCTXTYPE=%s" % ctxtype ],
        device=offload_device, debug=args.DBG)

fn = b.load_func("xdp_remGTP", mode, offload_device)

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
