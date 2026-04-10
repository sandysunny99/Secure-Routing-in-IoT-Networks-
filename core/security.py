"""
Security Module — Detection + Trust + Secure Rerouting
Merged single module for rank anomaly detection, trust scoring,
and secure rerouting of traffic away from malicious nodes.
"""

from utils import logger

# ─── Thresholds ─────────────────────────────────────────────────
TRUST_THRESHOLD = 0.4          # nodes below this are flagged
RANK_ANOMALY_RATIO = 0.5       # if advertised_rank < real_rank * ratio → suspicious
FORWARDING_THRESHOLD = 0.5     # if forwarding ratio < 50% → suspicious


class SecurityEngine:
    """Combined detection, trust computation, and secure rerouting."""

    def detect_rank_anomaly(self, nodes: dict, neighbors: dict, scenario: str) -> set:
        """
        Detect nodes advertising suspiciously low ranks.
        Returns set of flagged node IDs.
        """
        flagged = set()

        for nid, node in nodes.items():
            if node.is_root:
                continue

            # Check if advertised rank is much lower than expected
            if node.advertised_rank < node.rank * RANK_ANOMALY_RATIO:
                flagged.add(nid)
                node.flagged = True
                logger.log("ALERT",
                           f"Node {nid} advertising rank={node.advertised_rank} "
                           f"(expected ~{node.rank}) — RANK ANOMALY detected",
                           nid, scenario)

                # Check neighbor consistency
                nb_ids = neighbors.get(nid, [])
                for nb_id in nb_ids:
                    if nb_id in nodes and not nodes[nb_id].is_root:
                        nb = nodes[nb_id]
                        if nb.advertised_rank >= node.advertised_rank and nb.rank < node.rank:
                            logger.log("DEBUG",
                                       f"Neighbor Node {nb_id} (rank={nb.rank}) confirms anomaly at Node {nid}",
                                       nb_id, scenario)

        if not flagged:
            logger.log("INFO", "No rank anomalies detected", scenario=scenario)

        return flagged

    def detect_packet_drops(self, nodes: dict, scenario: str) -> set:
        """
        Detect nodes with abnormally low forwarding ratios.
        Returns set of flagged node IDs.
        """
        flagged = set()

        for nid, node in nodes.items():
            if node.is_root:
                continue

            total_handled = node.packets_forwarded + node.packets_dropped
            if total_handled == 0:
                continue

            fwd_ratio = node.packets_forwarded / total_handled

            if fwd_ratio < FORWARDING_THRESHOLD:
                flagged.add(nid)
                node.flagged = True
                logger.log("ALERT",
                           f"Node {nid} forwarding ratio={fwd_ratio:.1%} "
                           f"(dropped {node.packets_dropped}/{total_handled}) — SUSPICIOUS",
                           nid, scenario)

        return flagged

    def compute_trust(self, node) -> float:
        """
        Compute trust score for a single node.
        Trust = 0.5 * rank_consistency + 0.5 * forwarding_ratio
        Range: 0.0 (untrusted) to 1.0 (fully trusted)
        """
        # Rank consistency: 1.0 if advertised == real, 0.0 if hugely different
        if node.rank > 0:
            rank_diff = abs(node.advertised_rank - node.rank) / node.rank
            rank_score = max(0.0, 1.0 - rank_diff)
        else:
            rank_score = 1.0

        # Forwarding ratio
        total = node.packets_forwarded + node.packets_dropped
        if total > 0:
            fwd_score = node.packets_forwarded / total
        else:
            fwd_score = 1.0  # no data yet, assume good

        trust = 0.5 * rank_score + 0.5 * fwd_score
        return round(trust, 3)

    def compute_all_trust_scores(self, nodes: dict, neighbors: dict, scenario: str):
        """Compute and assign trust scores for all nodes."""
        for nid, node in nodes.items():
            if node.is_root:
                node.trust_score = 1.0
                continue

            node.trust_score = self.compute_trust(node)

            if node.trust_score < TRUST_THRESHOLD:
                node.flagged = True
                logger.log("SECURE",
                           f"Node {nid} flagged — trust={node.trust_score:.3f} "
                           f"(threshold={TRUST_THRESHOLD})",
                           nid, scenario)
            elif node.trust_score < 0.7:
                logger.log("DEBUG",
                           f"Node {nid} trust={node.trust_score:.3f} (borderline)",
                           nid, scenario)

    def secure_reroute(self, nodes: dict, neighbors: dict, flagged: set, scenario: str) -> list:
        """
        Reroute traffic away from flagged nodes.
        Returns list of rerouting actions taken.
        """
        actions = []

        for nid, node in nodes.items():
            if node.is_root or nid in flagged:
                continue

            # Check if current parent is flagged
            if node.parent in flagged:
                old_parent = node.parent
                nb_ids = neighbors.get(nid, [])

                # Find best alternative parent
                best_alt = None
                best_rank = float('inf')
                for nb_id in nb_ids:
                    if nb_id in flagged or nb_id not in nodes:
                        continue
                    nb = nodes[nb_id]
                    if nb.advertised_rank < best_rank:
                        best_rank = nb.advertised_rank
                        best_alt = nb_id

                if best_alt and best_alt != old_parent:
                    node.parent = best_alt
                    action = f"Node {nid}: rerouted from Node {old_parent} → Node {best_alt}"
                    actions.append(action)
                    logger.log("SECURE", f"Traffic rerouted: Node {nid} → Node {best_alt} (was Node {old_parent})", nid, scenario)

        if not actions:
            logger.log("INFO", "No rerouting needed", scenario=scenario)

        return actions

    def full_analysis(self, nodes: dict, neighbors: dict, scenario: str) -> dict:
        """Run complete security analysis: detect + trust + reroute."""
        # Step 1: Rank anomaly detection
        rank_flagged = self.detect_rank_anomaly(nodes, neighbors, scenario)

        # Step 2: Packet drop detection
        drop_flagged = self.detect_packet_drops(nodes, scenario)

        # Step 3: Combined flagged set
        all_flagged = rank_flagged | drop_flagged

        # Step 4: Compute trust scores
        self.compute_all_trust_scores(nodes, neighbors, scenario)

        # Step 5: Trust-based flagging
        trust_flagged = {nid for nid, n in nodes.items() if n.trust_score < TRUST_THRESHOLD}
        all_flagged |= trust_flagged

        # Step 6: Secure rerouting
        actions = self.secure_reroute(nodes, neighbors, all_flagged, scenario)

        return {
            "flagged_nodes": list(all_flagged),
            "trust_scores": {nid: n.trust_score for nid, n in nodes.items()},
            "reroute_actions": actions,
            "detection_accuracy": 1.0 if all(nodes[f].is_malicious for f in all_flagged if f in nodes) else 0.5,
        }
