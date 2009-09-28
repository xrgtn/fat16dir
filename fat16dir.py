#!/usr/bin/python

import sys
import os
import os.path
import re
import struct
import optparse

BR_DICT = {
    'bps': [0x0B, 2, '<H'],             # bytes per sector
    'spc': [0x0D, 1, 'B'],              # sectors per cluster
    'rsvd_sects': [0x0E, 2, '<H'],      # reserved sectors from boot record
    'n_fats': [0x10, 1, 'B'],           # number of FATs
    'rdents': [0x11, 2, '<H'],          # number of rootdir entries
    'spf': [0x16, 2, '<H'],             # sectors per FAT
    'spt': [0x18, 2, '<H'],             # sectors per track
    'heads': [0x1A, 2, '<H'],           # heads (sides)
    'magic': [0x1FE, 2, '<H'],          # boot record magic
}

DENTRY_DICT = {
    'nam': [0x00, 8, '8s'],             # short name (8 chars)
    'ext': [0x08, 3, '3s'],             # short extension (3 chars)
    'size': [0x1C, 4, '<I'],            # size in bytes
    'cluster': [0x1A, 2, '<H'],         # first cluster
    'flags': [0x0B, 1, 'B'],            # R/O, hidden, system etc.
    'lfncksum': [0x0D, 1, 'B'],         # LFN checksum
    'nt': [0x0C, 1, 'B'],               # unknown
    'lfnf': [0x00, 1, 'B'],             # LFN flags: isLast and index
    'lfn1': [0x01, 10, '10s'],          # LFN part1
    'lfn2': [0x0E, 12, '12s'],          # LFN part2
    'lfn3': [0x1C, 4, '4s'],            # LFN part3
}

ATTR_MASK_LIST = (('v', 0x08), ('d', 0x10), ('r', 0x01),
    ('h', 0x02), ('s', 0x04), ('a', 0x20))
ATTR2MASK_MAP = dict(ATTR_MASK_LIST)

def parse(fmt_dict, buf):
    d = dict()
    for (k, v) in fmt_dict.iteritems():
        d[k] = struct.unpack(v[2], buf[v[0]:v[0]+v[1]])[0]
    return d

# Blocks Chain (chain of sectors, clusters & so on)
class BChain:
    def __init__(self, f, blist, bsize = 512, boffs = 0):
        self.f = f              # device/file
        self.blist = blist      # list of block numbers
        self.bsize = bsize      # blosk size
        self.boffs = boffs      # block area offset
    def __len__(self):
        return len(self.blist) * self.bsize
    def offs(self, pos):
        n, p = divmod(pos, self.bsize)
        return self.boffs + self.blist[n] * self.bsize + p
    def _read(self, pos, size):
        # Reads data up to the end of sector.
        # Return less than the requested size when the requested region
        # spans several sectors
        buf = ''
        n, p = divmod(pos, self.bsize)
        o = self.boffs + self.blist[n] * self.bsize + p
        f.seek(o, os.SEEK_SET)
        # limit the requested size:
        if p + size > self.bsize: size = self.bsize - p
        # read until success or EOF:
        while len(buf) < size:
            b = f.read(size - len(buf))
            if b == '': raise IOError("EOF at sector #%i, byte #%i"
                % (self.blist[n], p + len(buf)))
            buf += b
        return buf
    def read(self, pos, size):
        buf = ''
        while len(buf) < size:
            b = self._read(pos + len(buf), size - len(buf))
            if b == '': raise IOError("EOF at pos %i" % (pos + len(buf)))
            buf += b
        return buf
    @classmethod
    def get(f, pos, size, blist = [0], bsize = 512, boffs = 0):
        tmp = BChain(f = f, blist = blist, bsize = 512, boffs = 0)
        return tmp.read(pos, size)

def get_dirents(d_chain):
    de_cnt = len(d_chain) / 32
    de_list = []
    cur_lfn_parts = dict()
    cur_lfn_cksum = cur_lfn_maxnum = cur_lfn_offs = None
    for i in range(0, de_cnt):
        de_buf = d_chain.read(i * 32, 32)
        if de_buf == '\0' * 32: break
        de = parse(DENTRY_DICT, de_buf)
        de['raw'] = de_buf
        de['ofs'] = d_chain.offs(i * 32)        # offset of SFN
        de['offs'] = de['ofs']                  # offset of LFN
        de['attrs'] = ''                        # string of 'flags'
        for a, m in ATTR_MASK_LIST:
            if de['flags'] & m: de['attrs'] += a
            else: de['attrs'] += '-'
        if de['flags'] == 0x0F:
            assert(de['cluster'] == 0x0000)
            if de['nam'][:1] == '\xe5': de['type'] = 'deln'
            else:
                de['type'] = 'lfn'
                de['lfni'] = de['lfnf'] & ~0x40
                if de['lfnf'] & 0x40: cur_lfn_maxnum = de['lfni']
                assert(de['lfni'] > 0 and de['lfni'] <= 20 and
                    (cur_lfn_maxnum is None or de['lfni'] <= cur_lfn_maxnum))
                assert(cur_lfn_cksum is None
                    or cur_lfn_cksum == de['lfncksum'])
                cur_lfn_parts[de['lfni']] = de['lfn1'] + de['lfn2']\
                    + de['lfn3']
                # FIXME: Calculate LFN offset as offset of the first
                # encountered LFN entry (not the one with isLast flag):
                if cur_lfn_offs is None: cur_lfn_offs = de['ofs']
        else:
            if de['flags'] == 0x08:
                de['type'] = 'vol'
                de['name'] = de['nam'].rstrip() + de['ext'].rstrip()
            elif de['nam'][:1] == '\xe5':
                if de['flags'] & ATTR2MASK_MAP['d']: de['type'] = 'deld'
                else: de['type'] = 'delf'
            else:
                if cur_lfn_parts:
                    assert(cur_lfn_maxnum == len(cur_lfn_parts.keys()))
                    de['namu'] = "".join([cur_lfn_parts[k]
                        for k in sorted(cur_lfn_parts.keys())])
                    assert(not (len(de['namu']) % 1))
                    de['name'] = ''
                    # Convert from little-endian byte representation of
                    # UCS16 string to Python's native unicode:
                    for i in range(0, len(de['namu'])/2):
                        (l, h) = struct.unpack('BB', de['namu'][i*2:i*2+2])
                        if not l and not h: break
                        de['name'] += unichr((h << 8) + l)
                    # Store LFN offset
                    de['offs'] = cur_lfn_offs
                else:
                    # LFN not provided, so use entry's short name instead:
                    de['name'] = de['nam'].rstrip()
                    if de['ext'].rstrip() != '':
                        de['name'] += '.' + de['ext'].rstrip()
                if de['flags'] & ATTR2MASK_MAP['d']: de['type'] = 'dir'
                else: de['type'] = 'file'
            cur_lfn_parts = dict()
            cur_lfn_cksum = cur_lfn_maxnum = cur_lfn_offs = None
            de_list.append(de)
    return de_list

# Get cluster list for the given directory entry
def get_clist(br, de):
    if de['type'] == 'vol':
        assert(de['size'] == 0 and de['cluster'] == 0)
        return []
    assert(de['type'] in ('dir', 'file'))
    assert(de['cluster'] >= 2 and de['cluster'] <= 0xFFF8
        or de['size'] == 0 and de['cluster'] == 0)
    fat1bchain = BChain(br['dev'], [0],
        bsize = br['spf'] * br['bps'], boffs = br['fat1offs'])
    assert(fat1bchain.read(0, 4) == '\xF8\xFF\xFF\xFF')
    c = de['cluster']
    clist = []
    while c >= 2 and c < 0xFFF7:
        clist.append(c)
        c = struct.unpack('<H', fat1bchain.read(c * 2, 2))[0]
    return clist

def ls_dirents(br, de_list):
    global opts
    for de in de_list:
        if de['type'] in ('delf', 'deld'): continue
        elif de['type'] in ('lfn', 'deln'): continue
        else:
            # Dir/file/volume label
            if opts.size == "bytes":
                s = " %10i" % de['size']
            elif opts.size == "clusters":
                s = " %5i" % len(get_clist(br, de))
            elif opts.size == "sectors":
                s = " %8i" % (len(get_clist(br, de)) * br['spc'])
            else: s = ""
            print '%5s +%08X%s %s' % (de['attrs'], de['offs'], s, de['name'])

def _ls_path(br, dir_cache, path_head_str, path_tail_list):
    de_list = get_dirents(dir_cache[path_head_str])
    if not path_tail_list: return ls_dirents(br, de_list)
    else:
        p, path_tail_list = path_tail_list[0], path_tail_list[1:]
        path_head_str = os.path.join(path_head_str, p)
        for de in de_list:
            if de['type'] == 'file' and de['name'] == p:
                return ls_dirents(br, [de])
            elif de['type'] == 'dir' and de['name'] == p:
                de_clist = get_clist(br, de)
                if path_head_str not in dir_cache:
                    de_cchain = BChain(br['dev'], blist = de_clist,
                        bsize = br['spc'] * br['bps'],
                        boffs = br['c0offs'])
                    dir_cache[path_head_str] = de_cchain
                return _ls_path(br, dir_cache, path_head_str,
                    path_tail_list)
        print "ERROR: \"%s\" doesn't exist" % path_head_str

def ls_path(br, dir_cache, path_str):
    splitpath = os.path.normcase(os.path.normpath(path_str)).split(os.path.sep)
    if splitpath[0] == '': splitpath = splitpath[1:]
    if splitpath[-1] in ('', '.'): splitpath = splitpath[:-1]
    return _ls_path(br, dir_cache, os.path.sep, splitpath)

if __name__ == '__main__':
    global opts
    op = optparse.OptionParser(
        "USAGE: %prog [options] <dev> <path1> [<path2> ...]")
    op.add_option("-b", "--byte", dest="size", action="store_const",
        help="print size in bytes", default=None, const="bytes")
    op.add_option("-c", "--clusters", dest="size", action="store_const",
        help="print size in clusters", default=None, const="clusters")
    op.add_option("-s", "--sectors", dest="size", action="store_const",
        help="print size in sectors", default=None, const="sectors")
    (opts, args) = op.parse_args()
    if len(args) < 2: op.error("incorrect number of arguments")
    f = file(args[0], 'r')
    br_buf = f.read(512)
    br = parse(BR_DICT, br_buf)
    assert(br['magic'] == 0xAA55)
    assert(br['bps'] in (256, 512, 2048))
    br['dev'] = f
    # byte offsets of FAT1, FAT2 & so on
    # (in fact, never saw more than two FATs on disk):
    for i in range(1, br['n_fats'] + 1):
        br['fat%ioffs' % i] = br['rsvd_sects'] * br['bps']\
            + i * br['spf'] * br['bps']
    # bytes per root directory:
    br['bprd'] = br['rdents'] * 32
    # sectors per root directory:
    br['sprd'] = (br['bprd'] + br['bps'] - 1) / br['bps']
    # byte offset of root directory:
    br['rd_offs'] = (br['rsvd_sects'] + br['n_fats'] * br['spf']) * br['bps']
    # byte offsets of cluster #2 and cluster #0:
    br['c2offs'] = br['rd_offs'] + br['sprd'] * br['bps']
    br['c0offs'] = br['c2offs'] - 2 * br['spc'] * br['bps']
    # print br
    # Pre-cache the root directory:
    dir_cache = {os.path.sep: BChain(f, [0],
        bsize = br['bprd'], boffs = br['rd_offs'])}
    for path in args[1:]: ls_path(br, dir_cache, path)

# vi:set sw=4 et:
