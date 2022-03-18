#!/usr/bin/python3
#
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from bcc import libbcc, table
import pyroute2, time, sys, argparse, ctypes, os

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

enum cn_idx {
    CN_VXLAN,
    CN_GTP,
    CN_MAX
};

enum cb_idx {
    CB_ETH,
    CB_VLAN,
    CB_IP4,
    CB_IP6,
    CB_TCP,
    CB_UDP,
    CB_VXLAN,
    CB_GTP,
    CB_MAX,
};

struct meta_info {
    uint8_t hdr_len[CB_MAX];
    uint8_t cur_ofs;
} __attribute__((aligned(4)));

BPF_ARRAY(dbg_opt, uint32_t, 1); // 0: off, 1: on
BPF_ARRAY(rem_total, uint64_t, CN_MAX);
BPF_PROG_ARRAY(parser, CB_MAX);

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

static inline void update_rem_total(uint32_t idx)
{
    uint64_t *rem_c;

    rem_c = rem_total.lookup(&idx);
    if (rem_c)
    {
        *rem_c += 1;
    }
    else
    {
        rem_total.update(&idx, (uint64_t []) {1} );
    }
}

// ethtype (in network order)
// jump to next program or return -1
static inline int dispatch_ethtype(struct CTXTYPE *ctx, uint16_t ethtype)
{
    switch (ethtype)
    {
    case htons(ETH_P_8021Q):
    case htons(ETH_P_8021AD):
        parser.call(ctx, CB_VLAN);
        break;
    case htons(ETH_P_IP):
        parser.call(ctx, CB_IP4);
        break;
    case htons(ETH_P_IPV6):
        parser.call(ctx, CB_IP6);
        break;
    default:
        break;
    }

    return -1;
}

// ethtype (in network order)
// jump to next program or return -1
static inline int dispatch_ethtype_vlan(struct CTXTYPE *ctx, uint16_t ethtype)
{
    switch (ethtype)
    {
    case htons(ETH_P_IP):
        parser.call(ctx, CB_IP4);
        break;
    case htons(ETH_P_IPV6):
        parser.call(ctx, CB_IP6);
        break;
    default:
        break;
    }

    return -1;
}

// proto (in network order)
// jump to next program or return -1
static inline int dispatch_ippro(struct CTXTYPE *ctx, uint16_t proto)
{
    switch (proto)
    {
    case IPPROTO_UDP:
        parser.call(ctx, CB_UDP);
        break;
    case IPPROTO_TCP:
        parser.call(ctx, CB_TCP);
        break;
    default:
        break;
    }

    return -1;
}

// port (in network order)
// jump to next program or return -1
static inline int dispatch_port(struct CTXTYPE *ctx, uint16_t port)
{
    switch (port)
    {
    case htons(4789):
        parser.call(ctx, CB_VXLAN);
        break;
    case htons(GTP1U_PORT):
        parser.call(ctx, CB_GTP);
        break;
    default:
        break;
    }

    return -1;
}

int cb_eth(struct CTXTYPE *ctx)
{
    void            *data_end;
    void            *data;
    struct          meta_info *meta;
    struct ethhdr   *eth;
    int             ret;

    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0)
        return XDP_PASS;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    #pragma unroll
    for (int i=0; i <sizeof(meta->hdr_len); i++)
    {
        meta->hdr_len[i] = 0;
    }

    eth = data;
    if ((void *)&eth[1] > data_end)
        return XDP_PASS;

    meta->hdr_len[CB_ETH] = sizeof(*eth);
    meta->cur_ofs = sizeof(*eth);

    if (is_dbg_on_ex())
    {
        bpf_trace_printk("eth ofs - %d" DBGLR, meta->cur_ofs);
    }

    dispatch_ethtype(ctx, eth->h_proto);
    return XDP_PASS;
}

int cb_vlan(struct CTXTYPE *ctx)
{
    void            *data_end;
    void            *data;
    struct          meta_info *meta;
    struct vlan_hdr *vhdr;
    int             len = 0, cur_ofs;
    uint16_t        next_proto;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    cur_ofs = meta->cur_ofs;

    #pragma unroll
    for (int i=0; i<2; i++)
    {
        vhdr = data + cur_ofs + len;

        if ((void *)&vhdr[1] > data_end)
        {
            return XDP_PASS;
        }

        next_proto = vhdr->h_vlan_encapsulated_proto;
        len += sizeof(*vhdr);

        if (!(next_proto == htons(ETH_P_8021Q) || next_proto == htons(ETH_P_8021AD)))
        {
            break;
        }
    }

    meta->hdr_len[CB_VLAN] = len;
    meta->cur_ofs = cur_ofs + len;

    if (is_dbg_on_ex())
    {
        bpf_trace_printk("vlan ofs - %d" DBGLR, meta->cur_ofs);
    }

    dispatch_ethtype_vlan(ctx, next_proto);

    return XDP_PASS;
}

int cb_ip4(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct iphdr        *iph;
    uint16_t            next_proto;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    iph = data + meta->cur_ofs;
    if ((void *)&iph[1] > data_end)
        return XDP_PASS;

    meta->hdr_len[CB_IP4] = iph->ihl << 2;
    meta->cur_ofs += iph->ihl << 2;

    if (is_dbg_on_ex())
    {
        bpf_trace_printk("ip4 ofs - %d" DBGLR, meta->cur_ofs);
    }

    dispatch_ippro(ctx, iph->protocol);

    return XDP_PASS;
}

int cb_ip6(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct ipv6hdr      *ip6h;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    ip6h = data + meta->cur_ofs;
    if ((void *)&ip6h[1] > data_end)
        return XDP_PASS;

    meta->hdr_len[CB_IP6] = sizeof(*ip6h);
    meta->cur_ofs += sizeof(*ip6h);

    if (is_dbg_on_ex())
    {
        bpf_trace_printk("ip6 ofs - %d" DBGLR, meta->cur_ofs);
    }

    dispatch_ippro(ctx, ip6h->nexthdr);

    return XDP_PASS;
}

int cb_udp(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct udphdr       *udph;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    udph = data + meta->cur_ofs;

    if ((void *)&udph[1] > data_end)
        return XDP_PASS;

    meta->hdr_len[CB_UDP] = sizeof(*udph);
    meta->cur_ofs += sizeof(*udph);

    if (is_dbg_on_ex())
    {
        bpf_trace_printk("udp ofs - %d" DBGLR, meta->cur_ofs);
    }

    dispatch_port(ctx, udph->dest);

    return XDP_PASS;
}

int cb_tcp(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct tcphdr       *tcph;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    tcph = data + meta->cur_ofs;

    if ((void *)&tcph[1] > data_end)
        return -1;

    meta->hdr_len[CB_TCP] = tcph->doff << 2;
    meta->cur_ofs += tcph->doff << 2;

    if (is_dbg_on_ex())
    {
        bpf_trace_printk("tcp ofs - %d" DBGLR,meta->cur_ofs);
    }

    dispatch_port(ctx, tcph->dest);

    return XDP_PASS;
}

int cb_vxlan(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    struct vxlan_t      *vxlanh;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    vxlanh = data + meta->cur_ofs;

    if ((void *)&vxlanh[1] > data_end)
        return XDP_PASS;

    meta->cur_ofs += sizeof(*vxlanh);

    meta->cur_ofs + sizeof(*vxlanh);

    if (is_dbg_on_ex())
    {
        bpf_trace_printk("vxlan ofs - %d" DBGLR, meta->cur_ofs);
    }

    bpf_xdp_adjust_head(ctx, meta->cur_ofs);

    update_rem_total(CN_VXLAN);

    return XDP_PASS;
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

int cb_gtp(struct CTXTYPE *ctx)
{
    void                *data_end;
    void                *data;
    struct meta_info    *meta;
    //refer to gtp1u_udp_encap_recv in linux kernel
    struct gtp1_header  *gtp1h;
    int                 hdr_len = sizeof(*gtp1h);

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    gtp1h = data + meta->cur_ofs;

    if ((void *)&gtp1h[1] > data_end)
        return XDP_PASS;

    if ((gtp1h->flags >> 5) != GTP_V1)
        return XDP_PASS;

    if (gtp1h->type != GTP_TPDU)
        return XDP_PASS;

    if (gtp1h->flags & GTP1_F_MASK)
        hdr_len += 4;

    meta->cur_ofs += hdr_len;
    meta->hdr_len[CB_GTP] = hdr_len;

    if (is_dbg_on_ex())
    {
        bpf_trace_printk("gtp1u ofs - %d" DBGLR, meta->cur_ofs);
    }

    {
        int         cut_len, l2_hdr_len;
        uint8_t     is_outer_ip4 = 0;
        uint8_t     is_inner_ip4 = 0;

        // need to cut inserted (ip/udp or tcp /gprs) part
        //    cut_len max: 60 + 60 + 12
        // l2_hdr_len max: 14 + 8
        cut_len    = meta->hdr_len[CB_IP4] + meta->hdr_len[CB_IP6] +
                     meta->hdr_len[CB_TCP] + meta->hdr_len[CB_UDP] +
                     meta->hdr_len[CB_GTP];
        l2_hdr_len = meta->hdr_len[CB_ETH] + meta->hdr_len[CB_VLAN];

        is_outer_ip4 = (meta->hdr_len[CB_IP4] > 0);
        is_inner_ip4 = is_ip4_hdr(data, data_end, meta->cur_ofs);

        if (is_inner_ip4 != is_outer_ip4)
        {
            // need to modify the ethertype
            l2_hdr_len -= 2;
        }

        // move eth + vlan headear forward to strip the gtp tunnel header
        #pragma unroll
        for (int i=0; i <22; i++)
        {
            char *src, *dst;

            if (i > l2_hdr_len)
                break;

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

        update_rem_total(CN_GTP);
    }

    return XDP_PASS;
}

"""

dbg_path        = '/sys/fs/bpf/dbg_' + os.path.basename(os.path.splitext(__file__)[0])
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

def toggle_kdbg(kpath, is_en):
    try:
        kdbg    = PinnedArray(kpath, ctypes.c_uint32, ctypes.c_uint32, 1)
        kdbg[0] = ctypes.c_uint32([0, 1][is_en])

    except:
        print("Failed to toggle bpf debug flag !!!")

    else:
        print("BPF debug flag is {}.".format(["disabled", "enabled"][is_en]))

def get_total(tbl):
    ret = 0
    for idx in tbl.keys():
        ret += tbl[idx].value

    return ret

parser = argparse.ArgumentParser(
            description='Used to remove the tunnel header (VXLAN/GTPv1-U) of mirrored packets.')

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
    toggle_kdbg(dbg_path, args.KDBG)
    exit(0)


if mode == BPF.XDP:
    ret = "XDP_DROP"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"

# load BPF program
b = BPF(text=c_text, 
        cflags=["-c", "-w", "-DKBUILD_MODNAME", '-DDBGLR="\\n"', "-DCTXTYPE=%s" % ctxtype ],
        device=offload_device, debug=args.DBG)

fn_ar = ["cb_eth", "cb_vlan", "cb_ip4", "cb_ip6",
         "cb_tcp", "cb_udp", "cb_vxlan", "cb_gtp"]

parser = b.get_table("parser")

cb_idx = 0
for fn_name in fn_ar:
    fn = b.load_func(fn_name, mode, offload_device)
    parser[ctypes.c_int(cb_idx)] = ctypes.c_int(fn.fd)
    cb_idx += 1

    if fn_name == "cb_eth":
        fn_eth = fn

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
    b.attach_xdp(device, fn_eth, flags)
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
    toggle_kdbg(dbg_path, True)
    print("Printing debug info,", end= " ")

print("hit CTRL+C to stop")

i = 0

while 1:
    try:
        time.sleep(sleep_sec)

        i += 1

        total_cnt = get_total(rem_total)

        print ("rem_total/pps : {}/{})".format(
            total_cnt, total_cnt/(i*sleep_sec)))

    except KeyboardInterrupt:
        print("Removing filter from device")
        break

if mode == BPF.XDP:
    b.remove_xdp(device, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
