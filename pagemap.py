import sys, struct, re, array

class processmap(object):
    def __init__(self, pid):
        self._pid = pid
        self._maps = []
        self._mapcache = {}
        self.readmap()

    def readmap(self):
        self._maps = []
        self._mapcache = {}
        self._empty = "\xff" * 1024
        class mapping(object): pass
        for l in file("/proc/%s/maps" % self._pid):
            m = re.match(r"(\w+)-(\w+) (\S+) (\S+) (\S+) (\d+)\s+(\S*)", l)
            start, end, prot, offset, dev, huh, name = m.groups()
            a = mapping()
            a.start = int(start, 16)
            a.end = int(end, 16)
            a.offset = int(offset, 16)
            a.prot = prot
            a.dev = dev
            a.name = name
            self._maps.append(a)
        self.data = file("/proc/%s/pagemap" % self._pid, "r", 0).read(3*2**20)

    def __getitem__(self, page):
        return self._mapcache[addr>>20][(addr>>12)&255]

    def maps(self):
        return self._maps

    def range(self, startaddr, endaddr):
        off = (startaddr / 4096) * 4 + 4
        size = ((endaddr - startaddr) / 4096) * 4
        return array.array("l", self.data[off:off+size])
        fm = file("/proc/%s/pagemap" % self._pid, "r", 0) # uncached
        fm.seek(off)
        return array.array("l", fm.read(size))

    def findmap(self, addr):
        for m in self._maps:
            if addr >= m.start and addr <= m.end:
                return m

class kpagemap(object):
    def __init__(self):
        self._maps = []
        self._mapcache = {}
        try:
            self.data = file("/proc/kpagemap", "r", 0).read(8*2**22)
        except:
            self.data = "\0" * 4 * 2**20

    def pages(self):
        return len(self.data) / 8 - 1

    def flags(self, start, end):
        return struct.unpack("Lxxxx" * (end-start), self.data[start * 8 + 8: end * 8 + 8])

    def counts(self, start, end):
        return struct.unpack("xxxxL" * (end-start), self.data[start * 8 + 8: end * 8 + 8])

    def range(self, start, end):
        return array.array("L", self.data[start * 8 + 8: end * 8 + 8])

    def __getitem__(self, page):
        off = (page + 1) * 8
        data = self.data[off:off + 8]
        return struct.unpack("LL", data)
