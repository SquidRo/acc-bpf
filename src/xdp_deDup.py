#!/usr/bin/python3
#
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from bcc import libbcc, table
import pyroute2, time, sys, argparse, ctypes, os

c_text = """
#include <uapi/linux/bpf.h>

enum op_idx {
    OP_DBG,
    OP_HLEN,
    OP_MAX,
};

enum cb_idx {
    CB_P0,
    CB_P1,
    CB_FIN = 7,
    CB_MATCH,
    CB_MAX,
};

#define LOOP_MAX_ONE_ROUND      20
#define DFLT_HASH_LEN           0xfff

/* max packet len = 240 * 7 + 12 (done in CB_FIN) */
const int LOOP_MAX_LEN = CB_FIN * LOOP_MAX_ONE_ROUND * 12;

struct meta_info {
    uint32_t    a;
    uint32_t    b;
    uint32_t    c;
    uint16_t    cur_ofs;
    uint8_t     cur_step;
} __attribute__((aligned(4)));

BPF_ARRAY(opt_tbl, uint32_t, OP_MAX);
BPF_PROG_ARRAY(parser, CB_MAX);
BPF_HASH(packet_hash, u32, u32, HT_MAX);
BPF_ARRAY(drop_total, uint64_t, 1);

// return -1 if failed
static inline int get_opt(uint32_t op_idx)
{
    uint32_t *opt_val;

    opt_val = opt_tbl.lookup(&op_idx);

    if (opt_val)
    {
        return *opt_val;
    }

    return -1;
}

// return default value if failed
static inline int get_opt_limit(void)
{
    int ret;

    ret = get_opt(OP_HLEN);

    if ((ret == -1) || (ret == 0))
        ret = DFLT_HASH_LEN;

    return ret;
}

static inline uint32_t
jhash_rot(uint32_t x, int k)
{
    return (x << k) | (x >> (32 - k));
}

static inline void
jhash_mix(uint32_t *a, uint32_t *b, uint32_t *c)
{
      *a -= *c; *a ^= jhash_rot(*c,  4); *c += *b;
      *b -= *a; *b ^= jhash_rot(*a,  6); *a += *c;
      *c -= *b; *c ^= jhash_rot(*b,  8); *b += *a;
      *a -= *c; *a ^= jhash_rot(*c, 16); *c += *b;
      *b -= *a; *b ^= jhash_rot(*a, 19); *a += *c;
      *c -= *b; *c ^= jhash_rot(*b,  4); *b += *a;
}

static inline void
jhash_final(uint32_t *a, uint32_t *b, uint32_t *c)
{
      *c ^= *b; *c -= jhash_rot(*b, 14);
      *a ^= *c; *a -= jhash_rot(*c, 11);
      *b ^= *a; *b -= jhash_rot(*a, 25);
      *c ^= *b; *c -= jhash_rot(*b, 16);
      *a ^= *c; *a -= jhash_rot(*c,  4);
      *b ^= *a; *b -= jhash_rot(*a, 14);
      *c ^= *b; *c -= jhash_rot(*b, 24);
}

/* Returns the Jenkins hash of bytes at 'p', starting from 'basis' (finish part).
 * calculate the hash for final run (< 12 bytes).
 */
int cb_hash_fin(struct CTXTYPE *ctx)
{
    void                *data = (void*)(long)ctx->data;
    void                *data_end = (void*)(long)ctx->data_end;
    struct meta_info    *meta;
    uint32_t            tmp_3w[3] = {0};
    uint8_t             *src_p, *dst_p;
    int                 limit;

    data_end = (void*)(long)ctx->data_end;
    data = (void*)(long)ctx->data;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    limit = get_opt_limit();

    src_p = data + (meta->cur_ofs & 0xfff);
    dst_p = tmp_3w;

    #pragma unroll
    for (int j =0; j <12; j++)
    {
        if (src_p +1 > data_end)
            break;

        dst_p[j] = *src_p;
    }

    meta->a += bpf_ntohl(tmp_3w[0]);
    meta->b += bpf_ntohl(tmp_3w[1]);
    meta->c += bpf_ntohl(tmp_3w[2]);

    jhash_final(&meta->a, &meta->b, &meta->c);

    if (get_opt(OP_DBG) > 0)
    {
        bpf_trace_printk("pf ofs  - %d" DBGLR, (void *)src_p - data);
        bpf_trace_printk("pf hash - %x" DBGLR, meta->c);
    }

    parser.call(ctx, CB_MATCH);

    return XDP_PASS;
}

/* Returns the Jenkins hash of bytes at 'p', starting from 'basis'.
 * caculate hash for part0 (<= 240 bytes)
 */
int cb_hash_p0(struct CTXTYPE *ctx)
{
    void                *data;
    void                *data_end;
    struct meta_info    *meta;
    uint32_t            a, b, c, cur_idx =0,
                        tmp_3w[3] = {0};
    uint32_t            len;
    uint8_t             *src_p, *dst_p;
    int                 limit, ret, basis = 0;

    ret = bpf_xdp_adjust_meta(ctx, -(int)sizeof(*meta));
    if (ret < 0)
        return XDP_PASS;

    data = (void*)(long)ctx->data;
    data_end = (void*)(long)ctx->data_end;

    len = data_end - data; // pkt = 0 ~ len -1

    a = b = c = 0xdeadbeef + len + basis;

    limit = get_opt_limit();

    if (get_opt(OP_DBG) > 0)
    {
        bpf_trace_printk("p0 lim  - %d" DBGLR, limit);
    }

    #pragma unroll
    for (int i =0; i <LOOP_MAX_ONE_ROUND; i++)
    {
        if ((cur_idx + 12 > len) || (cur_idx + 12 > limit))
            break;

        src_p = data + cur_idx;
        dst_p = tmp_3w;

        #pragma unroll
        for (int j =0; j <12; j++)
        {
            if (src_p +1 > data_end)
                break;

            dst_p[j] = *src_p;
        }

        a += bpf_ntohl(tmp_3w[0]);
        b += bpf_ntohl(tmp_3w[1]);
        c += bpf_ntohl(tmp_3w[2]);
        jhash_mix(&a, &b, &c);

        cur_idx += 12;
    }

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    meta->a = a;
    meta->b = b;
    meta->c = c;
    meta->cur_ofs  = cur_idx;
    meta->cur_step = 0;

    if (get_opt(OP_DBG) > 0)
    {
        bpf_trace_printk("p0 len  - %d" DBGLR, len);
        bpf_trace_printk("p0 ofs  - %d" DBGLR, cur_idx);
        bpf_trace_printk("p0 hash - %x" DBGLR, meta->c);
    }

    if ((len == cur_idx) || (cur_idx == limit))
    {
        parser.call(ctx, CB_MATCH);
    }
    else if ((len <= cur_idx + 12) || (limit <= cur_idx + 12))
    {
        parser.call(ctx, CB_FIN);
    }
    else
    {
        parser.call(ctx, CB_P1);
    }

    return XDP_PASS;
}

/* Returns the Jenkins hash of bytes at 'p', starting from 'basis'.
 * caculate hash for part1 (240 ~ 1680 bytes).
 */
int cb_hash_p1(struct CTXTYPE *ctx)
{
    void                *data = (void*)(long)ctx->data;
    void                *data_end = (void*)(long)ctx->data_end;
    struct meta_info    *meta;
    uint32_t            a, b, c, cur_idx,
                        tmp_3w[3] = {0};
    uint32_t            len = data_end - data;
    uint8_t             *src_p, *dst_p, cur_step;
    int                 limit;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    a = meta->a;
    b = meta->b;
    c = meta->c;
    cur_idx  = meta->cur_ofs;
    meta->cur_step += 1;
    cur_step = meta->cur_step;

    limit = get_opt_limit();

    if (get_opt(OP_DBG) > 0)
    {
        bpf_trace_printk("p%d lim  - %d" DBGLR, cur_step, limit);
    }

    #pragma unroll
    for (int i =0; i <LOOP_MAX_ONE_ROUND; i++)
    {
        if (  (cur_idx + 12 > len)
            ||(cur_idx >= LOOP_MAX_LEN) //make verifier happy
            ||(cur_idx + 12 > limit))
            break;

        data = (void*)(long)ctx->data;

        src_p = data + cur_idx;
        dst_p = tmp_3w;

        #pragma unroll
        for (int j =0; j <12; j++)
        {
            if (src_p +1 > data_end)
                break;

            dst_p[j] = *src_p;
        }

        a += bpf_ntohl(tmp_3w[0]);
        b += bpf_ntohl(tmp_3w[1]);
        c += bpf_ntohl(tmp_3w[2]);
        jhash_mix(&a, &b, &c);

        cur_idx += 12;
    }

    meta->a = a;
    meta->b = b;
    meta->c = c;
    meta->cur_ofs  = cur_idx;

    if (get_opt(OP_DBG) > 0)
    {
        bpf_trace_printk("p%d len  - %d" DBGLR, cur_step, len);
        bpf_trace_printk("p%d ofs  - %d" DBGLR, cur_step, cur_idx);
        bpf_trace_printk("p%d hash - %x" DBGLR, cur_step, meta->c);
    }

    if ((cur_idx == len) || (cur_idx == limit))
    {
        parser.call(ctx, CB_MATCH);
    }
    else if ((len <= cur_idx + 12) || (limit <= cur_idx + 12))
    {
        parser.call(ctx, CB_FIN);
    }
    else
    {
        parser.call(ctx, cur_step+1);
    }

    return XDP_PASS;
}

// drop the packet if hash already exists in table
int cb_hash_match(struct CTXTYPE *ctx)
{
    void                *data = (void*)(long)ctx->data;
    struct meta_info    *meta;
    uint32_t            *count;
    uint64_t            *drop_c;
    int                 rc = XDP_PASS;

    /* Check data_meta have room for meta_info struct */
    meta = (void *)(unsigned long)ctx->data_meta;
    if ((void *)&meta[1] > data)
        return XDP_PASS;

    count = packet_hash.lookup(&meta->c);

    if (count)  // check if this hash exists
    {
        *count += 1;

        drop_c = drop_total.lookup((uint32_t []) {0});
        if (drop_c)
        {
            *drop_c += 1;
        }
        else
        {
            drop_total.update( (uint32_t []) {0}, (uint64_t []) {1} );
        }

        rc = XDP_DROP;

        if (get_opt(OP_DBG) > 0)
        {
            bpf_trace_printk("drop hash - %x" DBGLR, meta->c);
        }
    }
    else        // if the hash for the key doesn't exist, create one
    {
        packet_hash.update(&meta->c, (uint32_t []) {1} );
    }

    return rc;
}
"""

dbg_path       = '/sys/fs/bpf/dbg_' + os.path.basename(os.path.splitext(__file__)[0])
flags          = 0
offload_device = None
mode           = BPF.XDP

class PinnedArray(table.Array):
    def __init__(self, map_path, keytype, leaftype, max_entries):
        map_fd = libbcc.lib.bpf_obj_get(ctypes.c_char_p(map_path.encode('utf-8')))
        if map_fd < 0:
            raise ValueError("Failed to open eBPF map")

        self.map_fd = map_fd
        self.Key = keytype
        self.Leaf = leaftype
        self.max_entries = max_entries

def set_opt_val(kpath, in_opt_tbl, opt_idx, val):
    opt_name = ["DBG", "HASH LEN"]

    try:
        if kpath != None:
            opt_tbl = PinnedArray(kpath, ctypes.c_uint32, ctypes.c_uint32, len(opt_name))
        else:
            opt_tbl = in_opt_tbl

        opt_tbl[opt_idx] = ctypes.c_uint32(val)

    except:
        print("Failed to set option : {} !!!".format(opt_name[opt_idx]))

    else:
        print("{} option value is {}.".format(opt_name[opt_idx], val))

def cfg_opt_tbl(kpath, bopt_tbl, args):
    for idx, opt in enumerate ([args.KDBG, args.HLEN]):
        if opt != None:
            set_opt_val(kpath, bopt_tbl, idx, opt)


parser = argparse.ArgumentParser(description='Used to discard duplicate packets.')
parser.add_argument('-d', '--dbg', dest='DBG', type=int, default=0,
                    help='debug flag for bcc')
parser.add_argument('--kdbg', dest='KDBG', action='store_const', const=True,
                    help='enable bpf debug message')
parser.add_argument('--no-kdbg', dest='KDBG', action='store_const', const=False,
                    help='disable bpf debug message')
parser.add_argument('--len', dest='HLEN', type=int,
                    help='max input stream length for hash method, default is no limit')
parser.add_argument('dev', nargs ='?',
                    help='device (required if not used to toggle bpf debug message)')

args = parser.parse_args()

if args.KDBG == None and args.HLEN == None:
    if args.dev == None:
        print("error: the following arguments are required: dev")
        exit (1)
    else:
        device = args.dev
else:
    if args.dev == None:
        cfg_opt_tbl(dbg_path, None, args)
        exit(0)
    else:
        device = args.dev

if mode == BPF.XDP:
    ret = "XDP_DROP"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"

sleep_sec = 0.5     # in seconds
tbl_size  = 1024    # hash table size

# load BPF program
b = BPF(text=c_text, cflags=["-c", "-w", "-DKBUILD_MODNAME",
        '-DDBGLR="\\n"', "-DCTXTYPE=%s" % ctxtype, "-DHT_MAX=%d" % tbl_size ],
        device=offload_device, debug=args.DBG)

fn_ar = ["cb_hash_p0", "cb_hash_p1", "cb_hash_p1", "cb_hash_p1", "cb_hash_p1",
         "cb_hash_p1", "cb_hash_p1", "cb_hash_fin", "cb_hash_match"]

parser = b.get_table("parser")

cb_idx = 0
for fn_name in fn_ar:
    fn = b.load_func(fn_name, mode, offload_device)
    parser[ctypes.c_int(cb_idx)] = ctypes.c_int(fn.fd)
    cb_idx += 1

    if fn_name == "cb_hash_p0":
        fn_ing = fn

opt_tbl = b.get_table("opt_tbl")
cfg_opt_tbl(None, opt_tbl, args)

try:
    if os.path.exists(dbg_path):
        os.remove(dbg_path)

    ret = libbcc.lib.bpf_obj_pin(opt_tbl.map_fd, ctypes.c_char_p(dbg_path.encode('utf-8')))
    if ret != 0:
        raise Exception("Failed to pin map !!!")

except:
    if args.DBG == 0:
        print("Option value in kernel can not be modified !!!")
        print("Plz execute \"mount -t bpf none /sys/fs/bpf\" first !!!\n")

if mode == BPF.XDP:
    b.attach_xdp(device, fn_ing, flags)
else:
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent="ffff:fff2", classid=1, direct_action=True)

packet_hash = b.get_table("packet_hash")
drop_total = b.get_table("drop_total")
sleep_sec = 0.5  # in seconds

if args.DBG != 0:
    set_opt_val(None, opt_tbl, 0, True)
    print("Printing debug info,", end= " ")
    sleep_sec = 1

print("hit CTRL+C to stop")

i = 0

while 1:
    try:
        if args.DBG != 0:
            time.sleep(sleep_sec)

            i += 1

            for k in packet_hash.keys():
                print("i/hash/val : {} {:08x} {} ".format(i, k.value, packet_hash[k].value))

            if (i % 7 == 0):
                print ("clear hash table (drop_total/pps : {}/{})".format(
                            drop_total[0].value, drop_total[0].value/(i*sleep_sec)))
                packet_hash.clear()
        else:
            # reset the hash table every 500 ms ???
            time.sleep(sleep_sec)
            packet_hash.clear()

    except KeyboardInterrupt:
        print("Removing filter from device")
        break

if mode == BPF.XDP:
    b.remove_xdp(device, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
