"""
RPL Network Simulation Engine
Lightweight simulation of RPL routing with static ranks,
basic parent selection, and simulated packet forwarding.
"""

import random
import time
from dataclasses import dataclass, field
from typing import Optional
from utils import logger

# ─── Configuration Constants ────────────────────────────────────
NUM_SENSORS = 6
MALICIOUS_NODE_ID = 8
ROOT_NODE_ID = 1
ROOT_RANK = 256
RANK_INCREMENT = 256           # rank increase per hop
NUM_ROUNDS = 20                # packets per sensor per scenario
ATTACK_DROP_RATE = 0.80        # malicious node drops 80% packets
FAKE_RANK = 128                # malicious node advertises LOWER than root
DEMO_DELAY = 0.08              # seconds between events (visual pacing)

# ─── Node Positions (for topology visualization) ────────────────
NODE_POSITIONS = {
    1: (300, 50),    # Root — top center
    2: (150, 180),   # Layer 1
    3: (450, 180),   # Layer 1
    4: (80, 340),    # Layer 2
    5: (220, 340),   # Layer 2
    6: (380, 340),   # Layer 2
    7: (550, 340),   # Layer 2
    8: (300, 220),   # Malicious — central, intercept position
}

# ─── Neighbor Adjacency (radio range) ──────────────────────────
# Node 8 is strategically placed to be within radio range of
# most leaf nodes, so it can attract their traffic via fake rank.
NEIGHBORS = {
    1: [2, 3],
    2: [1, 4, 5, 8],
    3: [1, 6, 7, 8],
    4: [2],             # Too far from Node 8 — clean path
    5: [2, 8],          # Can hear malicious node
    6: [3, 8],          # Can hear malicious node
    7: [3, 8],          # Can hear malicious node
    8: [2, 3, 5, 6, 7], # Malicious: hears most nodes
}


@dataclass
class RPLNode:
    """Lightweight RPL node representation."""
    node_id: int
    rank: int = 0
    parent: Optional[int] = None
    is_root: bool = False
    is_malicious: bool = False
    packets_sent: int = 0
    packets_received: int = 0
    packets_forwarded: int = 0
    packets_dropped: int = 0
    trust_score: float = 1.0
    advertised_rank: int = 0     # what node claims its rank is
    flagged: bool = False


class RPLNetwork:
    """Manages the full RPL DODAG network."""

    def __init__(self):
        self.nodes: dict[int, RPLNode] = {}
        self.edges: list[tuple[int, int]] = []   # parent-child links
        self.packets_total = 0
        self.packets_delivered = 0
        self.scenario = ""

    def setup(self, scenario: str, attack_enabled: bool = False, secure_enabled: bool = False):
        """Initialize network for a given scenario."""
        self.nodes.clear()
        self.edges.clear()
        self.packets_total = 0
        self.packets_delivered = 0
        self.scenario = scenario

        # Create root
        root = RPLNode(node_id=ROOT_NODE_ID, rank=ROOT_RANK, is_root=True)
        root.advertised_rank = ROOT_RANK
        self.nodes[ROOT_NODE_ID] = root
        logger.log("INFO", f"Node {ROOT_NODE_ID} initialized as DODAG root (rank={ROOT_RANK})", ROOT_NODE_ID, scenario)
        time.sleep(DEMO_DELAY)

        # Create sensor nodes
        for i in range(2, NUM_SENSORS + 2):
            node = RPLNode(node_id=i)
            self.nodes[i] = node

        # Create malicious node
        mal = RPLNode(node_id=MALICIOUS_NODE_ID, is_malicious=attack_enabled)
        self.nodes[MALICIOUS_NODE_ID] = mal

        # Assign ranks based on topology (BFS from root)
        self._assign_ranks(attack_enabled)

        # Parent selection
        self._select_parents(attack_enabled, secure_enabled)

        # Log node joins
        for nid in sorted(self.nodes.keys()):
            if nid == ROOT_NODE_ID:
                continue
            n = self.nodes[nid]
            role = ""
            if n.is_malicious:
                role = " [MALICIOUS]" if attack_enabled else ""
            parent_str = f"parent={n.parent}" if n.parent else "no parent"
            logger.log("INFO", f"Node {nid} joined network ({parent_str}, rank={n.rank}){role}", nid, scenario)
            time.sleep(DEMO_DELAY * 0.5)

    def _assign_ranks(self, attack_enabled: bool):
        """Assign ranks via BFS from root (static hop-based)."""
        visited = {ROOT_NODE_ID}
        queue = [ROOT_NODE_ID]
        hop = 0

        while queue:
            next_queue = []
            hop += 1
            for current in queue:
                for neighbor_id in NEIGHBORS.get(current, []):
                    if neighbor_id not in visited and neighbor_id in self.nodes:
                        node = self.nodes[neighbor_id]
                        node.rank = ROOT_RANK + hop * RANK_INCREMENT
                        node.advertised_rank = node.rank

                        # Malicious node advertises fake low rank
                        if node.is_malicious and attack_enabled:
                            node.advertised_rank = FAKE_RANK
                            logger.log("DEBUG", f"Node {neighbor_id} true rank={node.rank}, advertising rank={FAKE_RANK}", neighbor_id, self.scenario)

                        visited.add(neighbor_id)
                        next_queue.append(neighbor_id)
            queue = next_queue

    def _select_parents(self, attack_enabled: bool, secure_enabled: bool):
        """Each node selects the neighbor with lowest advertised rank as parent.
        Uses loop prevention: only selects neighbors that can reach the root."""
        from core.security import SecurityEngine
        se = SecurityEngine()
        flagged_nodes = set()

        # In secure mode, run detection first to identify suspicious nodes
        if secure_enabled and attack_enabled:
            flagged_nodes = se.detect_rank_anomaly(self.nodes, NEIGHBORS, self.scenario)

        # Track which nodes have a resolved path to root
        resolved = {ROOT_NODE_ID}

        # Process nodes in ascending real rank order (top-down)
        # Use advertised_rank as secondary key so that in attack mode,
        # the malicious node (with fake low advertised rank) gets resolved
        # first among same-rank peers, making it available as a parent.
        sorted_nodes = sorted(
            [(nid, n) for nid, n in self.nodes.items() if not n.is_root],
            key=lambda x: (x[1].rank, x[1].advertised_rank)
        )

        for nid, node in sorted_nodes:
            neighbors = NEIGHBORS.get(nid, [])
            best_parent = None
            best_rank = float('inf')

            for nb_id in neighbors:
                if nb_id not in self.nodes:
                    continue
                nb = self.nodes[nb_id]

                # In secure mode, skip flagged nodes
                if secure_enabled and nb_id in flagged_nodes:
                    continue

                # Only consider neighbors with advertised rank < this node's rank
                if nb.advertised_rank >= node.rank:
                    continue

                # Loop prevention: only pick neighbors that already reach root
                if nb_id not in resolved:
                    continue

                if nb.advertised_rank < best_rank:
                    best_rank = nb.advertised_rank
                    best_parent = nb_id

            node.parent = best_parent
            if best_parent:
                self.edges.append((best_parent, nid))
                resolved.add(nid)

    def run_data_rounds(self, num_rounds: int = NUM_ROUNDS, attack_enabled: bool = False, secure_enabled: bool = False):
        """Simulate data packet transmission from sensors to root."""
        logger.log("INFO", f"Starting data transmission ({num_rounds} rounds)", scenario=self.scenario)
        time.sleep(DEMO_DELAY)

        leaf_nodes = [nid for nid, n in self.nodes.items()
                      if not n.is_root and not n.is_malicious]

        for round_num in range(1, num_rounds + 1):
            for sender_id in leaf_nodes:
                self.packets_total += 1
                self.nodes[sender_id].packets_sent += 1

                # Trace path to root
                path = self._trace_path(sender_id)
                delivered = self._forward_packet(path, round_num, attack_enabled)

                if delivered:
                    self.packets_delivered += 1

            # Log progress every 5 rounds
            if round_num % 5 == 0:
                pdr = (self.packets_delivered / self.packets_total * 100) if self.packets_total else 0
                logger.log("DEBUG", f"Round {round_num}/{num_rounds} complete — PDR: {pdr:.1f}%", scenario=self.scenario)

            time.sleep(DEMO_DELAY * 0.3)

    def _trace_path(self, start_id: int) -> list:
        """Trace the path from a node to root via parent links."""
        path = [start_id]
        current = start_id
        visited = {start_id}
        while current != ROOT_NODE_ID:
            parent = self.nodes[current].parent
            if parent is None or parent in visited:
                break
            path.append(parent)
            visited.add(parent)
            current = parent
        return path

    def _forward_packet(self, path: list, round_num: int, attack_enabled: bool) -> bool:
        """Forward a packet along the path. Returns True if delivered to root."""
        for i, nid in enumerate(path):
            node = self.nodes[nid]

            if node.is_root:
                node.packets_received += 1
                if round_num <= 3:  # Only log first few rounds in detail
                    path_str = " -> ".join(f"Node {p}" for p in path)
                    logger.log("INFO", f"Data: {path_str} (root) [OK]", path[0], self.scenario)
                return True

            # Malicious node drops packets
            if node.is_malicious and attack_enabled and i > 0:
                if random.random() < ATTACK_DROP_RATE:
                    node.packets_dropped += 1
                    if round_num <= 5:
                        logger.log("ALERT", f"Packet DROPPED at Node {nid} (sinkhole active)", nid, self.scenario)
                    return False
                else:
                    node.packets_forwarded += 1
            elif i > 0:
                node.packets_forwarded += 1

        # Path didn't reach root
        return path[-1] == ROOT_NODE_ID

    def get_pdr(self) -> float:
        """Get Packet Delivery Ratio (0.0 - 1.0)."""
        if self.packets_total == 0:
            return 0.0
        return self.packets_delivered / self.packets_total

    def get_results(self) -> dict:
        """Get scenario results summary."""
        return {
            "scenario": self.scenario,
            "packets_total": self.packets_total,
            "packets_delivered": self.packets_delivered,
            "pdr": self.get_pdr(),
            "nodes": {nid: {
                "node_id": nid,
                "rank": n.rank,
                "advertised_rank": n.advertised_rank,
                "parent": n.parent,
                "is_root": n.is_root,
                "is_malicious": n.is_malicious,
                "packets_sent": n.packets_sent,
                "packets_received": n.packets_received,
                "packets_forwarded": n.packets_forwarded,
                "packets_dropped": n.packets_dropped,
                "trust_score": n.trust_score,
                "flagged": n.flagged,
                "position": NODE_POSITIONS.get(nid, (0, 0)),
            } for nid, n in self.nodes.items()},
            "edges": self.edges,
        }


def run_scenario(scenario: str) -> dict:
    """Run a single scenario and return results."""
    network = RPLNetwork()

    if scenario == "normal":
        logger.print_scenario_header("SCENARIO 1: NORMAL ROUTING")
        logger.print_pipeline({"Simulation": "active", "Detection": "pending", "Results": "pending"})
        network.setup("normal", attack_enabled=False, secure_enabled=False)
        network.run_data_rounds(attack_enabled=False)
        logger.print_pipeline({"Simulation": "done", "Detection": "done", "Results": "active"})

    elif scenario == "attack":
        logger.print_scenario_header("SCENARIO 2: SINKHOLE ATTACK")
        logger.print_pipeline({"Simulation": "active", "Detection": "pending", "Results": "pending"})
        network.setup("attack", attack_enabled=True, secure_enabled=False)
        network.run_data_rounds(attack_enabled=True)
        logger.print_pipeline({"Simulation": "done", "Detection": "done", "Results": "active"})

    elif scenario == "secure":
        logger.print_scenario_header("SCENARIO 3: SECURE ROUTING (TRUST-BASED)")
        logger.print_pipeline({"Simulation": "active", "Detection": "active", "Results": "pending"})
        network.setup("secure", attack_enabled=True, secure_enabled=True)

        # Run security engine
        from core.security import SecurityEngine
        se = SecurityEngine()
        se.compute_all_trust_scores(network.nodes, NEIGHBORS, "secure")

        logger.print_pipeline({"Simulation": "done", "Detection": "done", "Results": "pending"})
        network.run_data_rounds(attack_enabled=True, secure_enabled=True)
        logger.print_pipeline({"Simulation": "done", "Detection": "done", "Results": "active"})

    # Compute final trust scores
    from core.security import SecurityEngine
    se = SecurityEngine()
    se.compute_all_trust_scores(network.nodes, NEIGHBORS, scenario)

    pdr = network.get_pdr()
    level = "INFO" if pdr > 0.8 else ("ALERT" if pdr < 0.5 else "DEBUG")
    logger.log(level, f"Scenario '{scenario}' complete — PDR: {pdr*100:.1f}%", scenario=scenario)

    # Print node trust summary
    trust_rows = []
    for nid in sorted(network.nodes.keys()):
        n = network.nodes[nid]
        role = "Root" if n.is_root else ("Malicious" if n.is_malicious else "Sensor")
        trust_rows.append({
            "Node": f"Node {nid}",
            "Role": role,
            "Trust": n.trust_score,
            "PDR": pdr if n.is_root else (n.packets_forwarded / max(n.packets_forwarded + n.packets_dropped, 1)),
        })
    logger.print_summary_table(f"{scenario.upper()} — Node Summary", trust_rows)

    return network.get_results()


def run_all_scenarios() -> dict:
    """Run all 3 scenarios and return combined results."""
    results = {}
    for scenario in ["normal", "attack", "secure"]:
        results[scenario] = run_scenario(scenario)
        time.sleep(0.3)

    # Print comparison
    comparison = []
    for s in ["normal", "attack", "secure"]:
        comparison.append({
            "Scenario": s.capitalize(),
            "PDR": results[s]["pdr"],
            "Delivered": results[s]["packets_delivered"],
            "Total": results[s]["packets_total"],
        })
    logger.print_scenario_header("COMPARISON SUMMARY")
    logger.print_summary_table("ALL SCENARIOS — PDR Comparison", comparison)

    return results
