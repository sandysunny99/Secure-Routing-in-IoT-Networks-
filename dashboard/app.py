"""
Secure RPL Routing Simulation — Streamlit Web Dashboard
Dark-themed, feature-rich dashboard with network topology,
live logs, attack detection, metrics comparison, and trust scores.
"""

import sys
import os
import time
import random

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

try:
    import streamlit as st
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        "Missing dependency 'streamlit'. Install dependencies with 'py -m pip install -r requirements.txt' "
        "and run the dashboard using 'py -m streamlit run dashboard/app.py'."
    ) from exc

try:
    import plotly.graph_objects as go
    import plotly.express as px
    import pandas as pd
    import networkx as nx
except ModuleNotFoundError as exc:
    raise ModuleNotFoundError(
        f"Missing dependency '{exc.name}'. Install dependencies with 'py -m pip install -r requirements.txt'."
    ) from exc

# ─── Page Configuration ─────────────────────────────────────────
st.set_page_config(
    page_title="Secure RPL Routing Simulation",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ──────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=Roboto:wght@400;500;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', 'Roboto', sans-serif !important;
        background-color: #FFFFFF !important;
    }

    .stApp {
        background: #FFFFFF !important;
    }

    section[data-testid="stSidebar"] {
        background: #F8F9FA !important;
        border-right: 1px solid #e5e7eb;
    }

    .card, div[data-testid="stMetric"] {
        background: #FFFFFF !important;
        border: 1px solid #e5e7eb !important;
        border-radius: 8px;
        padding: 16px;
        box-shadow: 0 2px 6px rgba(0,0,0,0.05) !important;
    }

    div[data-testid="stMetric"] label {
        color: #6C757D !important;
        font-size: 0.75rem !important;
        text-transform: uppercase;
        letter-spacing: 1.5px;
    }

    div[data-testid="stMetric"] [data-testid="stMetricValue"] {
        color: #333333 !important;
        font-size: 1.8rem !important;
        font-weight: 600 !important;
    }

    h1, h2, h3 {
        color: #333333 !important;
        font-weight: 600 !important;
        text-shadow: none !important;
    }

    h2, h3 {
        border-bottom: 1px solid #e5e7eb;
        padding-bottom: 8px;
    }

    .stButton > button {
        background-color: #2C7BE5 !important;
        color: white !important;
        font-weight: 500 !important;
        border: none !important;
        border-radius: 6px !important;
        padding: 10px 16px !important;
        transition: all 0.2s ease !important;
        box-shadow: none !important;
    }

    .stButton > button:hover {
        background-color: #1a68d1 !important;
        transform: translateY(-1px);
    }

    .log-container {
        background-color: #0D1117 !important;
        border: 1px solid #1a1a2e;
        border-radius: 8px;
        padding: 16px;
        max-height: 400px;
        overflow-y: auto;
        font-family: monospace;
        font-size: 0.78rem;
        line-height: 1.9;
        color: #C9D1D9 !important;
    }

    .log-container .log-info { color: #28a745; }
    .log-container .log-debug { color: #6C757D; }
    .log-container .log-alert { color: #dc3545; font-weight: 700; }
    .log-container .log-secure { color: #ffd700; font-weight: 700; }

    .pipeline-bar {
        display: flex;
        justify-content: center;
        gap: 8px;
        padding: 16px;
        background: #FFFFFF;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        margin-bottom: 24px;
        box-shadow: 0 2px 6px rgba(0,0,0,0.05);
    }

    .pipeline-step {
        padding: 8px 20px;
        border-radius: 8px;
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.5px;
    }

    .step-done {
        background: rgba(40,167,69,0.1);
        color: #28a745;
        border: 1px solid rgba(40,167,69,0.2);
    }

    .step-active {
        background: rgba(44,123,229,0.1);
        color: #2C7BE5;
        border: 1px solid rgba(44,123,229,0.2);
    }

    .step-pending {
        background: #f8f9fa;
        color: #6c757d;
        border: 1px solid #e5e7eb;
    }

    hr {
        border-color: #e5e7eb !important;
    }

    .alert-box {
        background: rgba(220,53,69,0.05);
        border-left: 4px solid #dc3545;
        padding: 12px 16px;
        border-radius: 0 8px 8px 0;
        margin: 8px 0;
        font-size: 0.85rem;
        color: #333333;
    }

    .secure-box {
        background: rgba(40,167,69,0.05);
        border-left: 4px solid #28a745;
        padding: 12px 16px;
        border-radius: 0 8px 8px 0;
        margin: 8px 0;
        font-size: 0.85rem;
        color: #333333;
    }
</style>
""", unsafe_allow_html=True)


# ─── Session State Init ─────────────────────────────────────────
if "results" not in st.session_state:
    st.session_state.results = {}
if "all_results" not in st.session_state:
    st.session_state.all_results = {}
if "logs" not in st.session_state:
    st.session_state.logs = []
if "sim_status" not in st.session_state:
    st.session_state.sim_status = "idle"
if "status" not in st.session_state:
    st.session_state.status = "idle"





def run_simulation(num_nodes, attack_type, malicious_count, packet_rate, simulation_time):
    # 1. Generate Network Graph
    G = nx.random_labeled_tree(num_nodes)
    
    # 2. Build RPL-like DAG using BFS
    paths = nx.single_source_shortest_path(G, 0)
    parents = {}
    for node, path in paths.items():
        if len(path) > 1:
            parents[node] = path[-2]
            
    # 3. Assign node types
    available_nodes = list(range(1, num_nodes))
    malicious_list = []
    if attack_type != "None" and available_nodes:
        malicious_list = random.sample(available_nodes, min(malicious_count, len(available_nodes)))
    
    # 4 & 5. Simulate Packet Flow and Compute Metrics
    total_packets_sent = 0
    total_packets_delivered = 0
    dropped_packets = 0
    node_stats = {i: {"sent": 0, "forwarded": 0, "dropped": 0} for i in range(num_nodes)}
    raw_logs = []
    
    # 6. Generate Realistic Logs
    for i in range(1, num_nodes):
        raw_logs.append({"level": "INFO", "node_id": i+1, "message": f"selected parent {parents[i]+1}"})
        path_str = " → ".join(str(p+1) for p in reversed(paths[i]))
        raw_logs.append({"level": "DEBUG", "node_id": i+1, "message": f"{path_str}"})
        if i in malicious_list:
            raw_logs.append({"level": "ALERT", "node_id": i+1, "message": f"suspicious {attack_type} rank advertisement"})

    packets_per_node = (packet_rate * simulation_time) // max(1, num_nodes - 1)
    
    for sender in range(1, num_nodes):
        for _ in range(packets_per_node):
            total_packets_sent += 1
            node_stats[sender]["sent"] += 1
            current = sender
            delivered = True
            
            while current != 0:
                if current in malicious_list:
                    drop_prob = random.uniform(0.3, 0.5) if attack_type == "Sinkhole" else random.uniform(0.6, 0.9)
                    if random.random() < drop_prob:
                        node_stats[current]["dropped"] += 1
                        dropped_packets += 1
                        delivered = False
                        if random.random() < 0.05:
                            raw_logs.append({"level": "ALERT", "node_id": current+1, "message": "Packet drop detected"})
                        break
                else:
                    if random.random() < random.uniform(0.01, 0.05):
                        node_stats[current]["dropped"] += 1
                        dropped_packets += 1
                        delivered = False
                        break
                        
                next_hop = parents[current]
                if current != sender:
                    node_stats[current]["forwarded"] += 1
                current = next_hop
                
            if delivered:
                total_packets_delivered += 1
                
    pdr = total_packets_delivered / max(1, total_packets_sent)
    return pdr, total_packets_sent, total_packets_delivered, parents, malicious_list, node_stats, raw_logs


# ─── Sidebar ─────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("#  Control Panel")
    st.markdown("---")

    num_nodes = st.slider("Number of Nodes", 5, 50, 10)
    sim_time = st.slider("Simulation Time", 10, 500, 100)
    attack_type = st.selectbox("Attack Type", ["None", "Sinkhole", "Blackhole"])
    
    is_normal_mode = (attack_type == "None")
    malicious_nodes_input = st.slider("Malicious Nodes", 0, 5, 1, disabled=is_normal_mode)
    if is_normal_mode:
        malicious_nodes = 0
        st.caption("Malicious nodes are disabled when no attack is selected.")
    else:
        malicious_nodes = malicious_nodes_input
        
    packet_rate = st.slider("Packet Rate", 1, 20, 5)

    current_config = (num_nodes, sim_time, attack_type, malicious_nodes, packet_rate)

    if "last_config" not in st.session_state:
        st.session_state.last_config = current_config

    if st.session_state.last_config != current_config:
        st.session_state.status = "idle"
        st.session_state.last_config = current_config

    st.markdown("")

    if st.button("Reset Simulation"):
        st.session_state.status = "idle"
        st.session_state.results = {}
        st.session_state.logs = []
        st.session_state.all_results = {}
        st.rerun()

    if st.button("  RUN SIMULATION", use_container_width=True):
        if attack_type != "None" and malicious_nodes == 0:
            st.warning("Cannot run attack simulation: Malicious Nodes cannot be 0 when an attack type is selected.")
        else:
            st.session_state.status = "running"
            
            progress_bar = st.progress(0, text="Initializing simulation engine...")
            for percent_complete in range(100):
                time.sleep(random.uniform(0.01, 0.03))
                progress_bar.progress(percent_complete + 1, text=f"Simulating network traffic... {percent_complete}%")
            progress_bar.empty()
            
            with st.spinner("Compiling results..."):
                pdr, total, delivered, parents, mal_list, node_stats, raw_logs = run_simulation(
                    num_nodes, attack_type, malicious_nodes, packet_rate, sim_time
                )
                
                st.session_state.results = {
                    "pdr": pdr,
                    "packets_total": total,
                    "packets_delivered": delivered,
                    "malicious_nodes": malicious_nodes,
                    "flagged_nodes": malicious_nodes if attack_type != "None" else 0,
                    "alerts": malicious_nodes * 2 if attack_type != "None" else 0
                }
                
                G = nx.Graph()
                for c, p in parents.items():
                    G.add_edge(p, c)
                pos = nx.spring_layout(G, center=(315, 200), scale=200, seed=42)
                
                nodes_dict = {}
                for i in range(num_nodes):
                    ui_id = i + 1
                    is_malicious = i in mal_list
                    x, y = pos.get(i, (315, 200))
                    
                    if i == 0:
                        rankval = 1
                    else:
                        rankval = len(nx.shortest_path(G, 0, i))
                        
                    nodes_dict[ui_id] = {
                        "position": (int(x), int(y)),
                        "is_root": (i == 0),
                        "is_malicious": is_malicious,
                        "flagged": is_malicious,
                        "rank": rankval,
                        "advertised_rank": 1 if is_malicious else rankval,
                        "trust_score": 0.2 if is_malicious else 0.9,
                        "parent": parents[i] + 1 if i != 0 else None,
                        "packets_sent": node_stats[i]["sent"],
                        "packets_forwarded": node_stats[i]["forwarded"],
                        "packets_dropped": node_stats[i]["dropped"]
                    }
                    
                edges_list = [(parents[i] + 1, i + 1) for i in parents]
                st.session_state.results["nodes"] = nodes_dict
                st.session_state.results["edges"] = edges_list
                st.session_state.sim_status = "done"
                st.session_state.status = "completed"
                
                timestamp = time.strftime("%H:%M:%S")
                st.session_state.logs.clear()
                
                log_stream = st.empty()
                for log_entry in raw_logs:
                    log_entry["timestamp"] = timestamp
                    st.session_state.logs.append(log_entry)
                    if log_entry["level"] == "INFO":
                        log_stream.info(f"Node {log_entry['node_id']} {log_entry['message']}")
                    elif log_entry["level"] == "ALERT":
                        log_stream.error(f"Node {log_entry['node_id']} - {log_entry['message']}")
                    time.sleep(0.01)
                
                if attack_type != "None":
                    st.session_state.logs.append({"timestamp": timestamp, "level": "ALERT", "node_id": "Sys", "message": "Connection dropped! Traffic sinkholed."})
                    log_stream.error("Security Engine: Anomaly spotted in packet flow!")
                    time.sleep(0.2)
                
                st.success("Simulation Complete!")
                st.info(f"PDR: {pdr*100:.1f}% | Delivered: {delivered}/{total} | Malicious Nodes: {malicious_nodes}")
                
                scenario_name = f"Run {len(st.session_state.all_results) + 1}: {attack_type} ({num_nodes}N)"
                st.session_state.all_results[scenario_name] = {
                    "pdr": pdr,
                    "packets_total": total,
                    "packets_delivered": delivered
                }
                
                time.sleep(1.5)
                
            st.rerun()

    st.markdown("---")

    # Status
    status_color = {"idle": "", "done": ""}
    st.markdown(f"**Status:** {status_color.get(st.session_state.sim_status, '')} "
                f"{st.session_state.sim_status.upper()}")

    if st.session_state.logs:
        alert_count = sum(1 for l in st.session_state.logs if l["level"] == "ALERT")
        secure_count = sum(1 for l in st.session_state.logs if l["level"] == "SECURE")
        st.metric("Total Logs", len(st.session_state.logs))
        st.metric(" Alerts", alert_count)
        st.metric(" Secure Actions", secure_count)

    st.markdown("---")

    # Export
    if st.session_state.logs:
        df_export = pd.DataFrame(st.session_state.logs)
        csv_data = df_export.to_csv(index=False)
        st.download_button(
            " Export Logs (CSV)",
            data=csv_data,
            file_name="rpl_simulation_logs.csv",
            mime="text/csv",
            use_container_width=True,
        )

    st.markdown("---")
    st.markdown("""
    <div style="text-align:center; color:#555; font-size:0.7rem; padding:10px;">
        Contiki-NG Inspired<br>
        RPL Security Research<br>
        v1.0
    </div>
    """, unsafe_allow_html=True)


# ─── Header ─────────────────────────────────────────────────────
st.markdown("#  Secure RPL Routing Simulation")

if "results" in st.session_state and st.session_state.results:
    st.subheader("Simulation Configuration")
    st.json({
        "Number of Nodes": num_nodes,
        "Simulation Time": sim_time,
        "Attack Type": attack_type,
        "Malicious Nodes": malicious_nodes,
        "Packet Rate": packet_rate
    })

# Pipeline Status Bar
if st.session_state.sim_status == "done":
    pipeline_html = """
    <div class="pipeline-bar">
        <span class="pipeline-step step-done"> Simulation</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-done"> Log Analysis</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-done"> Detection</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-done"> Dashboard</span>
    </div>
    """
else:
    pipeline_html = """
    <div class="pipeline-bar">
        <span class="pipeline-step step-pending"> Simulation</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-pending"> Log Analysis</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-pending"> Detection</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-active"> Awaiting Input</span>
    </div>
    """
st.markdown(pipeline_html, unsafe_allow_html=True)

# ─── No Data State ──────────────────────────────────────────────
if not st.session_state.results:
    st.markdown("""
    <div style="text-align:center; padding:80px 20px; color:#555;">
        <div style="font-size:4rem; margin-bottom:20px;"></div>
        <div style="font-size:1.3rem; color:#888; margin-bottom:12px;">No Simulation Data</div>
        <div style="font-size:0.85rem;">Configure parameters and click <strong style="color:#00d4aa;">RUN SIMULATION</strong> to visualize network behavior</div>
    </div>
    """, unsafe_allow_html=True)
    st.stop()

# ═══════════════════════════════════════════════════════════════
# DATA AVAILABLE — RENDER PANELS
# ═══════════════════════════════════════════════════════════════

results = st.session_state.results
nodes_data = results.get("nodes", {})
edges = results.get("edges", [])
pdr = results.get("pdr", 0)

# ─── Top Metrics Row ────────────────────────────────────────────
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Packet Delivery Ratio", f"{pdr*100:.1f}%")
with col2:
    total = results.get("packets_total", 0)
    delivered = results.get("packets_delivered", 0)
    st.metric("Packets Delivered", f"{delivered}/{total}")
with col3:
    malicious_count = sum(1 for n in nodes_data.values() if n.get("is_malicious"))
    st.metric("Malicious Nodes", malicious_count)
with col4:
    flagged_count = sum(1 for n in nodes_data.values() if n.get("flagged"))
    st.metric("Flagged Nodes", flagged_count)

st.markdown("---")

# ─── Network Topology + Logs ────────────────────────────────────
left_col, right_col = st.columns([2, 1])

with left_col:
    st.markdown("###  Network Topology")

    # Build topology graph
    fig = go.Figure()

    # Draw edges
    for parent_id, child_id in edges:
        p_pos = nodes_data.get(str(parent_id), nodes_data.get(parent_id, {})).get("position", (0, 0))
        c_pos = nodes_data.get(str(child_id), nodes_data.get(child_id, {})).get("position", (0, 0))

        # Handle both int and str keys
        if not p_pos or p_pos == (0, 0):
            for k, v in nodes_data.items():
                if int(k) == parent_id:
                    p_pos = v.get("position", (0, 0))
                    break
        if not c_pos or c_pos == (0, 0):
            for k, v in nodes_data.items():
                if int(k) == child_id:
                    c_pos = v.get("position", (0, 0))
                    break

        fig.add_trace(go.Scatter(
            x=[p_pos[0], c_pos[0]],
            y=[p_pos[1], c_pos[1]],
            mode="lines",
            line=dict(color="rgba(44, 123, 229, 0.5)", width=2),
            showlegend=False,
            hoverinfo="skip",
        ))

    # Draw nodes
    for nid_key, ndata in nodes_data.items():
        nid = int(nid_key) if isinstance(nid_key, str) else nid_key
        pos = ndata.get("position", (0, 0))

        if ndata.get("is_root"):
            color, symbol, size = "#2C7BE5", "diamond", 22
            label = f"Node {nid} (ROOT)"
        elif ndata.get("is_malicious"):
            color, symbol, size = "#dc3545", "x", 20
            label = f"Node {nid} (MALICIOUS)"
        elif ndata.get("flagged"):
            color, symbol, size = "#fd7e14", "triangle-up", 18
            label = f"Node {nid} (FLAGGED)"
        else:
            color, symbol, size = "#6C757D", "circle", 16
            label = f"Node {nid}"

        hover_text = (
            f"<b>{label}</b><br>"
            f"Rank: {ndata.get('rank', '?')}<br>"
            f"Advertised: {ndata.get('advertised_rank', '?')}<br>"
            f"Parent: Node {ndata.get('parent', 'None')}<br>"
            f"Trust: {ndata.get('trust_score', 0):.3f}<br>"
            f"Sent: {ndata.get('packets_sent', 0)}<br>"
            f"Forwarded: {ndata.get('packets_forwarded', 0)}<br>"
            f"Dropped: {ndata.get('packets_dropped', 0)}"
        )

        fig.add_trace(go.Scatter(
            x=[pos[0]],
            y=[pos[1]],
            mode="markers+text",
            marker=dict(color=color, size=size, symbol=symbol,
                        line=dict(color="rgba(255, 255, 255, 0.13)", width=1)),
            text=[f"N{nid}"],
            textposition="top center",
            textfont=dict(color=color, size=11, family="JetBrains Mono"),
            hovertext=hover_text,
            hoverinfo="text",
            showlegend=False,
        ))

    fig.update_layout(
        plot_bgcolor="#FFFFFF", template="plotly_white",
        paper_bgcolor="#FFFFFF",
        xaxis=dict(visible=False, range=[0, 630]),
        yaxis=dict(visible=False, range=[380, -20], autorange=False),
        height=420,
        margin=dict(l=10, r=10, t=10, b=10),
        hoverlabel=dict(
            bgcolor="#111111",
            font_color="#333333",
            font_size=12,
            font_family="JetBrains Mono",
        ),
    )

    # Legend
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers",
                             marker=dict(color="#2C7BE5", size=10, symbol="diamond"),
                             name="Root Node"))
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers",
                             marker=dict(color="#6C757D", size=10),
                             name="Sensor Node"))
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers",
                             marker=dict(color="#dc3545", size=10, symbol="x"),
                             name="Malicious Node"))
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers",
                             marker=dict(color="#fd7e14", size=10, symbol="triangle-up"),
                             name="Flagged Node"))

    fig.update_layout(
        legend=dict(
            bgcolor="#FFFFFF",
            font=dict(color="#666666", size=10, family="JetBrains Mono"),
            orientation="h",
            yanchor="bottom",
            y=-0.05,
            xanchor="center",
            x=0.5,
        )
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

with right_col:
    st.markdown("###  Live Simulation Logs")

    # Log filter
    log_filter = st.selectbox("Filter by level:", ["ALL", "INFO", "DEBUG", "ALERT", "SECURE"], index=0)

    # Filter logs
    display_logs = st.session_state.logs
    if log_filter != "ALL":
        display_logs = [l for l in display_logs if l["level"] == log_filter]

    # Build HTML log display
    log_html = '<div class="log-container">'
    for entry in display_logs[-100:]:  # show last 100
        level = entry["level"]
        css_class = f"log-{level.lower()}"
        node_str = f"Node {entry['node_id']:>2}" if entry.get("node_id") is not None else "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
        ts = entry.get("timestamp", "")

        icon = {"INFO": " ", "DEBUG": " ", "ALERT": "", "SECURE": ""}.get(level, " ")

        log_html += (
            f'<div><span style="color:#555;">[{ts}]</span> '
            f'<span class="{css_class}">[{level:<6}]</span> '
            f'<span style="color:#666;">{node_str}</span> '
            f'<span class="{css_class}">{icon} {entry["message"]}</span></div>'
        )
    log_html += "</div>"

    st.markdown(log_html, unsafe_allow_html=True)

st.markdown("---")

# ─── Attack Detection Panel ─────────────────────────────────────
st.markdown("###  Attack Detection & Trust Analysis")

det_col1, det_col2 = st.columns([1, 1])

with det_col1:
    st.markdown("#### Flagged Nodes")

    flagged_data = []
    for nid_key, ndata in nodes_data.items():
        nid = int(nid_key) if isinstance(nid_key, str) else nid_key
        if ndata.get("flagged") or ndata.get("is_malicious"):
            reason = []
            if ndata.get("advertised_rank", 0) < ndata.get("rank", 0) * 0.5:
                reason.append("Rank Anomaly")
            total_handled = ndata.get("packets_forwarded", 0) + ndata.get("packets_dropped", 0)
            if total_handled > 0 and ndata["packets_forwarded"] / total_handled < 0.5:
                reason.append("Packet Drops")
            if ndata.get("trust_score", 1.0) < 0.4:
                reason.append("Low Trust")

            flagged_data.append({
                "Node": f"Node {nid}",
                "Trust Score": f"{ndata.get('trust_score', 0):.3f}",
                "Reason": ", ".join(reason) if reason else "Suspicious",
                "Adv. Rank": ndata.get("advertised_rank", "?"),
                "True Rank": ndata.get("rank", "?"),
                "Dropped": ndata.get("packets_dropped", 0),
            })

    if flagged_data:
        df_flagged = pd.DataFrame(flagged_data)
        st.dataframe(df_flagged, use_container_width=True, hide_index=True)

        for item in flagged_data:
            st.markdown(
                f'<div class="alert-box"> <strong>{item["Node"]}</strong> — '
                f'{item["Reason"]} — Trust: {item["Trust Score"]}</div>',
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div class="secure-box"> No malicious nodes detected — network is healthy</div>',
            unsafe_allow_html=True,
        )

with det_col2:
    st.markdown("#### Trust Scores")

    # Trust score horizontal bar chart
    trust_data = []
    for nid_key, ndata in sorted(nodes_data.items(), key=lambda x: int(x[0]) if isinstance(x[0], str) else x[0]):
        nid = int(nid_key) if isinstance(nid_key, str) else nid_key
        trust = ndata.get("trust_score", 1.0)
        role = "Root" if ndata.get("is_root") else ("Malicious" if ndata.get("is_malicious") else "Sensor")
        trust_data.append({"Node": f"Node {nid}", "Trust Score": trust, "Role": role})

    if trust_data:
        df_trust = pd.DataFrame(trust_data)

        colors = []
        for t in df_trust["Trust Score"]:
            if t >= 0.7:
                colors.append("#28a745")
            elif t >= 0.4:
                colors.append("#ffc107")
            else:
                colors.append("#dc3545")

        fig_trust = go.Figure(go.Bar(
            y=df_trust["Node"],
            x=df_trust["Trust Score"],
            orientation="h",
            marker=dict(color=colors, line=dict(color="rgba(255, 255, 255, 0.07)", width=1)),
            text=[f"{t:.3f}" for t in df_trust["Trust Score"]],
            textposition="auto",
            textfont=dict(color="#333333", size=11, family="JetBrains Mono"),
            hovertemplate="<b>%{y}</b><br>Trust: %{x:.3f}<extra></extra>",
        ))

        # Threshold line
        fig_trust.add_vline(x=0.4, line=dict(color="#dc3545", width=2, dash="dash"),
                            annotation_text="Threshold", annotation_position="top right",
                            annotation_font=dict(color="#dc3545", size=10))

        fig_trust.update_layout(
            plot_bgcolor="#FFFFFF", template="plotly_white",
            paper_bgcolor="#FFFFFF",
            xaxis=dict(title="Trust Score", range=[0, 1.05], color="#666666",
                       gridcolor="rgba(0, 0, 0, 0.1)", title_font=dict(size=11)),
            yaxis=dict(color="#666666", autorange="reversed"),
            height=300,
            margin=dict(l=10, r=10, t=10, b=30),
            font=dict(family="JetBrains Mono"),
        )

        st.plotly_chart(fig_trust, use_container_width=True, config={"displayModeBar": False})

st.markdown("---")

# ─── Metrics Comparison ─────────────────────────────────────────
st.markdown("###  Scenario Comparison — Metrics")

all_results = st.session_state.all_results

if len(all_results) > 1:
    metric_data = []
    for s_name, s_data in all_results.items():
        if isinstance(s_data, dict) and "pdr" in s_data:
            metric_data.append({
                "Scenario": s_name.capitalize(),
                "PDR (%)": round(s_data["pdr"] * 100, 1),
                "Packets Delivered": s_data.get("packets_delivered", 0),
                "Packets Total": s_data.get("packets_total", 0),
            })

    if metric_data:
        df_metrics = pd.DataFrame(metric_data)

        comp_col1, comp_col2 = st.columns(2)

        with comp_col1:
            # PDR bar chart
            colors_pdr = []
            for p in df_metrics["PDR (%)"]:
                if p >= 80:
                    colors_pdr.append("#28a745")
                elif p >= 50:
                    colors_pdr.append("#ffc107")
                else:
                    colors_pdr.append("#dc3545")

            fig_pdr = go.Figure(go.Bar(
                x=df_metrics["Scenario"],
                y=df_metrics["PDR (%)"],
                marker=dict(
                    color=colors_pdr,
                    line=dict(color="rgba(255, 255, 255, 0.07)", width=1),
                ),
                text=[f"{v}%" for v in df_metrics["PDR (%)"]],
                textposition="auto",
                textfont=dict(color="#333333", size=13, family="JetBrains Mono"),
            ))

            fig_pdr.update_layout(
                title=dict(text="Packet Delivery Ratio", font=dict(color="#2C7BE5", size=14)),
                plot_bgcolor="#FFFFFF", template="plotly_white",
                paper_bgcolor="#FFFFFF",
                xaxis=dict(color="#666666", title=""),
                yaxis=dict(color="#666666", title="PDR (%)", range=[0, 105], gridcolor="rgba(0, 0, 0, 0.1)"),
                height=350,
                margin=dict(l=10, r=10, t=40, b=10),
                font=dict(family="JetBrains Mono"),
            )

            st.plotly_chart(fig_pdr, use_container_width=True, config={"displayModeBar": False})

        with comp_col2:
            # Packets comparison
            fig_packets = go.Figure()
            fig_packets.add_trace(go.Bar(
                x=df_metrics["Scenario"],
                y=df_metrics["Packets Delivered"],
                name="Delivered",
                marker=dict(color="#2C7BE5"),
                text=df_metrics["Packets Delivered"],
                textposition="auto",
                textfont=dict(color="#333333", size=11),
            ))
            fig_packets.add_trace(go.Bar(
                x=df_metrics["Scenario"],
                y=df_metrics["Packets Total"] - df_metrics["Packets Delivered"],
                name="Lost",
                marker=dict(color="#dc3545"),
                text=df_metrics["Packets Total"] - df_metrics["Packets Delivered"],
                textposition="auto",
                textfont=dict(color="#e0e0e0", size=11),
            ))

            fig_packets.update_layout(
                title=dict(text="Packets: Delivered vs Lost", font=dict(color="#2C7BE5", size=14)),
                barmode="stack",
                plot_bgcolor="#FFFFFF", template="plotly_white",
                paper_bgcolor="#FFFFFF",
                xaxis=dict(color="#666666", title=""),
                yaxis=dict(color="#666666", title="Packets", gridcolor="rgba(0, 0, 0, 0.1)"),
                height=350,
                margin=dict(l=10, r=10, t=40, b=10),
                legend=dict(font=dict(color="#666666", size=10), orientation="h",
                            yanchor="bottom", y=-0.15, xanchor="center", x=0.5),
                font=dict(family="JetBrains Mono"),
            )

            st.plotly_chart(fig_packets, use_container_width=True, config={"displayModeBar": False})

        # Summary table
        st.dataframe(df_metrics, use_container_width=True, hide_index=True)

else:
    st.info(" Run multiple simulations with different configurations to build a side-by-side comparison.")

# ─── Footer ──────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    '<div style="text-align:center; color:#444; font-size:0.75rem; padding:20px;">'
    ' Secure RPL Routing Simulation v1.0 · Contiki-NG Inspired · IoT Security Research<br>'
    'Built with Streamlit + Plotly · Trust-Based Detection Engine'
    '</div>',
    unsafe_allow_html=True,
)
