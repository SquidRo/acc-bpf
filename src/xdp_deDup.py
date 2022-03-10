#!/usr/bin/python3
#
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import pyroute2
import time
import sys, argparse

c_text = """
#include <uapi/linux/bpf.h>

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

/* Returns the Jenkins hash of bytes at 'p', starting from 'basis'.
 * len of data is 360 bytes or less.
 */
static inline uint32_t my_hash_bytes(void *data, void *data_end, uint32_t basis)
{
    uint32_t a, b, c, tmp_3w[3] = {0}, cur_idx =0;
    uint32_t len =  data_end - data, i, j;
    uint8_t  *src_p, *dst_p;

    a = b = c = 0xdeadbeef + len + basis;

    #pragma unroll
    for (i =0; i <30; i++) {
        if (cur_idx + 12> len)
            break;

        src_p = data + cur_idx;
        dst_p = tmp_3w;

        #pragma unroll
        for (j =0; j <12; j++) {
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

    if ((len > cur_idx) && (len - cur_idx < 12))
    {
        tmp_3w[0] = tmp_3w[1] = tmp_3w[2] =0;

        src_p = data + cur_idx;
        dst_p = tmp_3w;

        #pragma unroll
        for (j =0; j <12; j++) {
            if (src_p +1 > data_end)
                break;

            dst_p[j] = *src_p;
        }

        a += bpf_ntohl(tmp_3w[0]);
        b += bpf_ntohl(tmp_3w[1]);
        c += bpf_ntohl(tmp_3w[2]);
        jhash_final(&a, &b, &c);
    }

    return c;
}

BPF_HASH(packet_hash, u32, u32, HT_MAX);
BPF_ARRAY(drop_total, uint64_t, 1);

int xdp_dedup(struct CTXTYPE *ctx)
{
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    uint32_t *count, hash_res;
    uint64_t *drop_c;
    int rc = XDP_PASS;

    hash_res = my_hash_bytes(data, data_end, 0);

#ifdef DEBUG_HASH
    bpf_trace_printk("hash - %x\\n", hash_res);
#endif

    count = packet_hash.lookup(&hash_res);

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
    }
    else        // if the hash for the key doesn't exist, create one
    {
        packet_hash.update(&hash_res, (uint32_t []) {1} );
    }

    return rc;
}
"""

parser = argparse.ArgumentParser(description='Used to discard duplicate packets.')
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

sleep_sec = 0.5     # in seconds
tbl_size  = 1024    # hash table size

# load BPF program
b = BPF(text=c_text, cflags=["-c", "-w", "-DKBUILD_MODNAME",
        "-DCTXTYPE=%s" % ctxtype, "-DHT_MAX=%d" % tbl_size, ["", "-DDEBUG_HASH"][args.DBG != 0] ],
        device=offload_device, debug=args.DBG)

fn = b.load_func("xdp_dedup", mode, offload_device)

if mode == BPF.XDP:
    b.attach_xdp(device, fn, flags)
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
