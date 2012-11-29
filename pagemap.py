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
        self.data = file("/proc/%s/pagemap" % self._pid, "r", 0).read(6*2**20)

    def __getitem__(self, page):
        return self._mapcache[addr>>20][(addr>>12)&255]

    def maps(self):
        return self._maps

    def range(self, startaddr, endaddr):
        off = (startaddr / 4096) * 8
        size = ((endaddr - startaddr) / 4096)
        d = self.data[off:off + size * 8]
        if len(d):
            q = "Q" * size
            l = struct.unpack(q, d)
            return l;
        return []
        fm = file("/proc/%s/pagemap" % self._pid, "r", 0) # uncached
        fm.seek(off)
        l = fm.read(size)
        return l

    def findmap(self, addr):
        for m in self._maps:
            if addr >= m.start and addr <= m.end:
                return m

class archmap(object):
    def __init__(self, source):
	self.source = source
        m = self.memory()
        try:
            apo = m['archpfnoffset']
        except:
            apo = 0
        self._pfn_offset = apo

    def _read(self, f):
        return file(self.source + '/proc/' + f).read()

    def _readlines(self, f):
        return self._read(f).splitlines(True)

    def memdata(self):
        return self._readlines('meminfo')

    def memory(self):
        t = {}
        f = re.compile('(\\S+):\\s+(\\d+)')
        for l in self.memdata():
            m = f.match(l)
            if m:
                t[m.group(1).lower()] = int(m.group(2))
        return t

    def pfn_offset(self):
        return self._pfn_offset

class kpagecount(object):
    def __init__(self, source):
        self.l = ""
        try:
            self.data = file(source + "/proc/kpagecount", "r", 0).read(8*2**22)
        except:
            self.data = "\0" * 4 * 2**20

    def pages(self):
        return len(self.data) / 8

    def counts(self, start, end):
        if len(self.l) != (end-start):
            self.l = "Q" * (end-start)
        return struct.unpack(self.l,
                             buffer(self.data, start * 8, end * 8 - start * 8))

    def __getitem__(self, page):
        off = page * 8
        data = self.data[off:off + 8]
        return struct.unpack("Q", data)

class kpageflags(object):
    def __init__(self, source):
        self.l = ""
        try:
            self.data = file(source + "/proc/kpageflags", "r", 0).read(8*2**22)
        except:
            self.data = "\0" * 4 * 2**20

    def pages(self):
        return len(self.data) / 8

    def flags(self, start, end):
        if len(self.l) != (end-start):
            self.l = "Q" * (end-start)
        return struct.unpack(self.l,
                             buffer(self.data, start * 8, end * 8 - start * 8))

    def __getitem__(self, page):
        off = page * 8
        data = self.data[off:off + 8]
        return struct.unpack("Q", data)

class kpageorder(object):
    def __init__(self, source):
        self.l = ""
        try:
            self.data = file(source + "/proc/kpageorder", "r", 0).read(8*2**22)
        except:
            self.data = "\0" * 4 * 2**20

    def pages(self):
        return len(self.data) / 8

    def orders(self, start, end):
        if len(self.l) != (end-start):
            self.l = "Q" * (end-start)
        return struct.unpack(self.l,
                             buffer(self.data, start * 8, end * 8 - start * 8))

    def __getitem__(self, page):
        off = page * 8
        data = self.data[off:off + 8]
        return struct.unpack("Q", data)

class kpagetype(object):
    def __init__(self, source):
        self.l = ""
        try:
            self.data = file(source + "/proc/kpagetype", "r", 0).read(8*2**22)
        except:
            self.data = "\0" * 4 * 2**20

    def pages(self):
        return len(self.data) / 8

    def types(self, start, end):
        if len(self.l) != (end-start):
            self.l = "Q" * (end-start)
        return struct.unpack(self.l,
                             buffer(self.data, start * 8, end * 8 - start * 8))

    def __getitem__(self, page):
        off = page * 8
        data = self.data[off:off + 8]
        return struct.unpack("Q", data)

class kpagecskip(object):
    def __init__(self, source):
        self.l = ""
        try:
            self.data = file(source + "/proc/kpagecskip", "r", 0).read(8*2**22)
        except:
            self.data = "\0" * 4 * 2**20

    def pages(self):
        return len(self.data) / 8

    def flags(self, start, end):
        if len(self.l) != (end-start):
            self.l = "Q" * (end-start)
        return struct.unpack(self.l,
                             buffer(self.data, start * 8, end * 8 - start * 8))

    def __getitem__(self, page):
        off = page * 8
        data = self.data[off:off + 8]
        return struct.unpack("Q", data)
