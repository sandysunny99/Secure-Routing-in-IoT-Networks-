"""Debug the paths in attack scenario."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.simulation import RPLNetwork, NEIGHBORS

net = RPLNetwork()
net.setup("attack", attack_enabled=True, secure_enabled=False)

with open('results/debug.txt', 'w') as f:
    f.write("=== NODE INFO ===\n")
    for nid in sorted(net.nodes.keys()):
        n = net.nodes[nid]
        f.write(f"  Node {nid}: rank={n.rank} adv_rank={n.advertised_rank} parent={n.parent} malicious={n.is_malicious}\n")

    f.write("\n=== PATHS TO ROOT ===\n")
    for nid in sorted(net.nodes.keys()):
        if net.nodes[nid].is_root or net.nodes[nid].is_malicious:
            continue
        path = net._trace_path(nid)
        f.write(f"  Node {nid}: {' -> '.join(str(p) for p in path)}\n")

    f.write(f"\n=== EDGES: {net.edges} ===\n")

print("Debug written to results/debug.txt")
