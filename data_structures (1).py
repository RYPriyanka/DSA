# data_structures.py
import ipaddress
import hashlib
import random
import time
import tracemalloc
import sys


# -----------------------------
# Bloom Filter
# -----------------------------
class BloomFilter:
    def __init__(self, size=20000, hash_count=6):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [0] * size

    def _hashes(self, data):
        out = []
        for i in range(self.hash_count):
            h = int(hashlib.sha1((str(data) + str(i)).encode()).hexdigest(), 16)
            out.append(h % self.size)
        return out

    def add(self, data):
        for h in self._hashes(data):
            self.bit_array[h] = 1

    def might_contain(self, data):
        return all(self.bit_array[h] == 1 for h in self._hashes(data))


# -----------------------------
# Cuckoo Filter (simple)
# -----------------------------
class CuckooFilter:
    def __init__(self, capacity=8192, bucket_size=4, max_kicks=500):
        self.capacity = capacity
        self.bucket_size = bucket_size
        self.max_kicks = max_kicks
        self.buckets = [[] for _ in range(capacity)]

    def _hash(self, item):
        return int(hashlib.md5(str(item).encode()).hexdigest(), 16)

    def _indexes(self, item):
        h1 = self._hash(item) % self.capacity
        h2 = (h1 ^ self._hash(str(item))) % self.capacity
        return h1, h2

    def add(self, item):
        i1, i2 = self._indexes(item)
        if len(self.buckets[i1]) < self.bucket_size:
            self.buckets[i1].append(item)
            return True
        if len(self.buckets[i2]) < self.bucket_size:
            self.buckets[i2].append(item)
            return True
        i = random.choice([i1, i2])
        cur = item
        for _ in range(self.max_kicks):
            if not self.buckets[i]:
                self.buckets[i].append(cur)
                return True
            j = random.randrange(len(self.buckets[i]))
            self.buckets[i][j], cur = cur, self.buckets[i][j]
            i = (i ^ self._hash(str(cur))) % self.capacity
            if len(self.buckets[i]) < self.bucket_size:
                self.buckets[i].append(cur)
                return True
        return False

    def contains(self, item):
        i1, i2 = self._indexes(item)
        return item in self.buckets[i1] or item in self.buckets[i2]


# -----------------------------
# Patricia Trie
# -----------------------------
class PatriciaTrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False
        self.route_info = None

class PatriciaTrie:
    def __init__(self):
        self.root = PatriciaTrieNode()

    def insert(self, prefix, route_info):
        net = ipaddress.ip_network(prefix, strict=False)
        bits = self._ip_to_binary(net.network_address)[:net.prefixlen]
        node = self.root
        for b in bits:
            node = node.children.setdefault(b, PatriciaTrieNode())
        node.is_end = True
        node.route_info = route_info

    def lpm_search(self, ip):
        bits = self._ip_to_binary(ip)
        node = self.root
        best = None
        for b in bits:
            if b in node.children:
                node = node.children[b]
                if node.is_end:
                    best = node.route_info
            else:
                break
        return best

    def _ip_to_binary(self, ip):
        addr = ipaddress.ip_address(ip)
        return bin(int(addr))[2:].zfill(addr.max_prefixlen)


# -----------------------------
# LC-Trie (level-compressed)
# -----------------------------
class LCTrieNode:
    def __init__(self, prefix=""):
        self.prefix = prefix
        self.children = {}
        self.route_info = None

class LCTrie:
    def __init__(self):
        self.root = LCTrieNode()

    def insert(self, prefix, route_info):
        net = ipaddress.ip_network(prefix, strict=False)
        bits = self._ip_to_binary(net.network_address)[:net.prefixlen]
        node = self.root
        i = 0
        while i < len(bits):
            b = bits[i]
            if b not in node.children:
                node.children[b] = LCTrieNode(prefix=bits[i:])
                node.children[b].route_info = route_info
                return
            child = node.children[b]
            # find common prefix length
            common = 0
            a = child.prefix
            b_suffix = bits[i:]
            while common < len(a) and common < len(b_suffix) and a[common] == b_suffix[common]:
                common += 1
            if common == len(a):
                i += common
                node = child
            else:
                existing_suffix = a[common:]
                new_child = LCTrieNode(prefix=existing_suffix)
                new_child.children = child.children
                new_child.route_info = child.route_info

                child.prefix = a[:common]
                child.children = {existing_suffix[0]: new_child}
                child.route_info = None

                rest = b_suffix[common:]
                if rest:
                    child.children[rest[0]] = LCTrieNode(prefix=rest)
                    child.children[rest[0]].route_info = route_info
                else:
                    child.route_info = route_info
                return
        node.route_info = route_info

    def lpm_search(self, ip):
        bits = self._ip_to_binary(ip)
        node = self.root
        i = 0
        best = None
        while i < len(bits):
            b = bits[i]
            if b not in node.children:
                break
            child = node.children[b]
            if bits[i:].startswith(child.prefix):
                i += len(child.prefix)
                node = child
                if node.route_info is not None:
                    best = node.route_info
            else:
                break
        return best

    def _ip_to_binary(self, ip):
        addr = ipaddress.ip_address(ip)
        return bin(int(addr))[2:].zfill(addr.max_prefixlen)


# -----------------------------
# Radix Tree (multi-bit stride)
# -----------------------------
class RadixNode:
    def __init__(self):
        self.children = {}
        self.route_info = None

class RadixTree:
    def __init__(self, stride=8):
        self.root = RadixNode()
        self.stride = stride

    def insert(self, prefix, route_info):
        net = ipaddress.ip_network(prefix, strict=False)
        bits = self._ip_to_binary(net.network_address)[:net.prefixlen]
        node = self.root
        for i in range(0, len(bits), self.stride):
            key = bits[i:i + self.stride]
            node = node.children.setdefault(key, RadixNode())
        node.route_info = route_info

    def lpm_search(self, ip):
        bits = self._ip_to_binary(ip)
        node = self.root
        best = None
        for i in range(0, len(bits), self.stride):
            key = bits[i:i + self.stride]
            if key in node.children:
                node = node.children[key]
                if node.route_info is not None:
                    best = node.route_info
            else:
                break
        return best

    def _ip_to_binary(self, ip):
        addr = ipaddress.ip_address(ip)
        return bin(int(addr))[2:].zfill(addr.max_prefixlen)


# -----------------------------
# Trie + DAG (simple map-based LPM)
# -----------------------------
class TrieDAG:
    def __init__(self):
        self.map = {}

    def insert(self, prefix, route_info):
        norm = str(ipaddress.ip_network(prefix, strict=False))
        self.map[norm] = route_info

    def lpm_search(self, ip):
        addr = ipaddress.ip_address(ip)
        for plen in range(addr.max_prefixlen, -1, -1):
            net = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
            key = f"{net.network_address}/{plen}"
            if key in self.map:
                return self.map[key]
        return None


# -----------------------------
# Hash Table with LPM (dict)
# -----------------------------
class HashTable:
    def __init__(self):
        self.table = {}

    def insert(self, prefix, route_info):
        norm = str(ipaddress.ip_network(prefix, strict=False))
        self.table[norm] = route_info

    def lpm_search(self, ip):
        addr = ipaddress.ip_address(ip)
        for plen in range(addr.max_prefixlen, -1, -1):
            net = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
            key = f"{net.network_address}/{plen}"
            if key in self.table:
                return self.table[key]
        return None


# -----------------------------
# Utility
# -----------------------------
def normalize_prefix(prefix):
    return str(ipaddress.ip_network(prefix, strict=False))


# -----------------------------
# Structure wrapper: Filter + Underlying DS
# -----------------------------
class FilteredStructure:
    def __init__(self, name, filter_obj, ds_obj):
        self.name = name
        self.filter = filter_obj  # BloomFilter or CuckooFilter
        self.ds = ds_obj          # PatriciaTrie, LCTrie, RadixTree, TrieDAG, HashTable
        self.map = {}             # store prefix->route as fallback and for prob filters

    def insert(self, prefix, route_info):
        norm = normalize_prefix(prefix)
        # add to filter
        if hasattr(self.filter, "add"):
            self.filter.add(norm)
        # insert into underlying DS where possible
        if hasattr(self.ds, "insert"):
            try:
                self.ds.insert(norm, route_info)
            except Exception:
                # fallback: store in map
                self.map[norm] = route_info
        else:
            self.map[norm] = route_info

    def lpm_search(self, ip):
        # Try candidate prefixes from longest to shortest
        addr = ipaddress.ip_address(ip)
        for plen in range(addr.max_prefixlen, -1, -1):
            net = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
            key = f"{net.network_address}/{plen}"
            # check filter first
            if hasattr(self.filter, "might_contain"):
                if not self.filter.might_contain(key):
                    continue
            elif hasattr(self.filter, "contains"):
                if not self.filter.contains(key):
                    continue
            # if filter says yes, consult underlying DS or fallback map
            if hasattr(self.ds, "lpm_search"):
                res = self.ds.lpm_search(ip)
                if res:
                    return res
            if key in self.map:
                return self.map[key]
        return None


# -----------------------------
# Benchmark runner
# -----------------------------
def run_benchmark(prefixes, test_ips):
    # create filtered combinations
    structures = [
        FilteredStructure("Bloom + PatriciaTrie", BloomFilter(size=max(4000, len(prefixes)*4)), PatriciaTrie()),
        FilteredStructure("Bloom + LC-Trie", BloomFilter(size=max(4000, len(prefixes)*4)), LCTrie()),
        FilteredStructure("Bloom + RadixTree", BloomFilter(size=max(4000, len(prefixes)*4)), RadixTree(stride=8)),
        FilteredStructure("Bloom + Trie+DAG", BloomFilter(size=max(4000, len(prefixes)*4)), TrieDAG()),
        FilteredStructure("Bloom + HashTable", BloomFilter(size=max(4000, len(prefixes)*4)), HashTable()),
        FilteredStructure("Cuckoo + PatriciaTrie", CuckooFilter(capacity=max(2048, len(prefixes)//2)), PatriciaTrie()),
        FilteredStructure("Cuckoo + LC-Trie", CuckooFilter(capacity=max(2048, len(prefixes)//2)), LCTrie()),
        FilteredStructure("Cuckoo + RadixTree", CuckooFilter(capacity=max(2048, len(prefixes)//2)), RadixTree(stride=8)),
        FilteredStructure("Cuckoo + Trie+DAG", CuckooFilter(capacity=max(2048, len(prefixes)//2)), TrieDAG()),
        FilteredStructure("Cuckoo + HashTable", CuckooFilter(capacity=max(2048, len(prefixes)//2)), HashTable()),
    ]

    results = []
    for s in structures:
        # insertion
        tracemalloc.start()
        t0 = time.perf_counter()
        for pfx, rinfo in prefixes:
            s.insert(pfx, rinfo)
        insert_time = time.perf_counter() - t0
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # lookup
        t0 = time.perf_counter()
        found = 0
        for ip in test_ips:
            res = s.lpm_search(ip)
            if res:
                found += 1
        lookup_time = time.perf_counter() - t0

        approx_mem = peak + sys.getsizeof(s)
        results.append({
            "name": s.name,
            "insert_time": insert_time,
            "lookup_time": lookup_time,
            "mem": approx_mem,
            "found": found
        })
    return results
