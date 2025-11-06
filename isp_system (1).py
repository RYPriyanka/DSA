# isp_system.py
import ipaddress
from data_structures import PatriciaTrie, BloomFilter, normalize_prefix


# -----------------------------
# ISPTable + MultiISPSystem
# -----------------------------
class ISPTable:
    def __init__(self, name):
        self.name = name
        self.trie = PatriciaTrie()
        self.bloom = BloomFilter(size=5000, hash_count=5)
        self.routes = {}

    def add_route(self, prefix, next_hop, metric):
        route_info = {"next_hop": next_hop, "metric": metric}
        norm = normalize_prefix(prefix)
        self.trie.insert(norm, route_info)
        self.bloom.add(norm)
        self.routes[norm] = route_info

    def lookup(self, ip):
        return self.trie.lpm_search(ip)

    def visualize_routes(self):
        out = []
        for k, v in self.routes.items():
            out.append(f"{k} → {v}")
        return out


class MultiISPSystem:
    def __init__(self):
        self.isps = {}

    def add_isp(self, name):
        if name not in self.isps:
            self.isps[name] = ISPTable(name)
            return True
        return False

    def add_route(self, isp_name, prefix, next_hop, metric):
        if isp_name in self.isps:
            self.isps[isp_name].add_route(prefix, next_hop, metric)
            return True
        return False

    def lookup(self, ip):
        for isp in self.isps.values():
            result = isp.lookup(ip)
            if result:
                return isp.name, result
        return None, None

    def collect_all_routes(self):
        all_routes = []
        for isp in self.isps.values():
            for p, r in isp.routes.items():
                all_routes.append((p, r))
        return all_routes
