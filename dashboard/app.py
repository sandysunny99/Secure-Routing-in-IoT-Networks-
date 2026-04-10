"""
Secure RPL Routing Simulation — Streamlit Web Dashboard
Dark-themed, feature-rich dashboard with network topology,
live logs, attack detection, metrics comparison, and trust scores.
"""

import sys
import os
import time

# Ensure project root is on path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

# ─── Page Configuration ─────────────────────────────────────────
st.set_page_config(
    page_title="Secure RPL Routing Simulation",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ──────────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&display=swap');

    /* Global font */
    html, body, [class*="css"] {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Main background */
    .stApp {
        background: linear-gradient(180deg, #0a0a0a 0%, #0d1117 100%);
    }

    /* Metric cards */
    div[data-testid="stMetric"] {
        background: linear-gradient(135deg, #111111 0%, #1a1a2e 100%);
        border: 1px solid #00d4aa33;
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 4px 20px rgba(0, 212, 170, 0.08);
    }

    div[data-testid="stMetric"] label {
        color: #00d4aa !important;
        font-size: 0.75rem !important;
        text-transform: uppercase;
        letter-spacing: 1.5px;
    }

    div[data-testid="stMetric"] [data-testid="stMetricValue"] {
        color: #ffffff !important;
        font-size: 1.8rem !important;
        font-weight: 700 !important;
    }

    /* Headers */
    h1 {
        color: #00d4aa !important;
        text-shadow: 0 0 20px rgba(0, 212, 170, 0.3);
        font-weight: 700 !important;
        letter-spacing: -0.5px;
    }

    h2, h3 {
        color: #e0e0e0 !important;
        border-bottom: 1px solid #00d4aa33;
        padding-bottom: 8px;
    }

    /* Sidebar styling */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0d1117 0%, #111111 100%) !important;
        border-right: 1px solid #00d4aa22;
    }

    section[data-testid="stSidebar"] h1 {
        font-size: 1.2rem !important;
    }

    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #00d4aa 0%, #00b894 100%) !important;
        color: #0a0a0a !important;
        font-weight: 700 !important;
        border: none !important;
        border-radius: 8px !important;
        padding: 10px 24px !important;
        font-family: 'JetBrains Mono', monospace !important;
        letter-spacing: 0.5px;
        transition: all 0.3s ease !important;
        box-shadow: 0 4px 15px rgba(0, 212, 170, 0.25) !important;
    }

    .stButton > button:hover {
        box-shadow: 0 6px 25px rgba(0, 212, 170, 0.45) !important;
        transform: translateY(-1px);
    }

    /* Expander */
    .streamlit-expanderHeader {
        background-color: #111111 !important;
        border: 1px solid #00d4aa33 !important;
        border-radius: 8px !important;
        color: #00d4aa !important;
    }

    /* Select box */
    .stSelectbox > div > div {
        background-color: #111111 !important;
        border-color: #00d4aa44 !important;
    }

    /* Log container */
    .log-container {
        background: #0d0d0d;
        border: 1px solid #1a1a2e;
        border-radius: 8px;
        padding: 16px;
        max-height: 400px;
        overflow-y: auto;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        line-height: 1.9;
    }

    .log-info { color: #00ff88; }
    .log-debug { color: #00b4d8; }
    .log-alert { color: #ff4444; font-weight: 700; }
    .log-secure { color: #ffd700; font-weight: 700; }

    /* Pipeline bar */
    .pipeline-bar {
        display: flex;
        justify-content: center;
        gap: 8px;
        padding: 16px;
        background: linear-gradient(135deg, #111111 0%, #1a1a2e 100%);
        border: 1px solid #00d4aa22;
        border-radius: 12px;
        margin-bottom: 24px;
    }

    .pipeline-step {
        padding: 8px 20px;
        border-radius: 8px;
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.5px;
        font-family: 'JetBrains Mono', monospace;
    }

    .step-done {
        background: #00d4aa22;
        color: #00d4aa;
        border: 1px solid #00d4aa44;
    }

    .step-active {
        background: #ffd70022;
        color: #ffd700;
        border: 1px solid #ffd70044;
        animation: pulse 1.5s infinite;
    }

    .step-pending {
        background: #ffffff08;
        color: #666;
        border: 1px solid #ffffff11;
    }

    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.6; }
    }

    /* Divider */
    hr {
        border-color: #00d4aa22 !important;
    }

    /* Alert box */
    .alert-box {
        background: #ff444411;
        border-left: 4px solid #ff4444;
        padding: 12px 16px;
        border-radius: 0 8px 8px 0;
        margin: 8px 0;
        font-size: 0.85rem;
    }

    .secure-box {
        background: #ffd70011;
        border-left: 4px solid #ffd700;
        padding: 12px 16px;
        border-radius: 0 8px 8px 0;
        margin: 8px 0;
        font-size: 0.85rem;
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


def run_simulation_for_dashboard(scenario: str) -> dict:
    """Run simulation and capture results + logs."""
    from utils import logger
    from core.simulation import run_scenario, run_all_scenarios

    logger.clear()

    if scenario == "all":
        results = run_all_scenarios()
        st.session_state.all_results = results
        st.session_state.results = results.get("secure", results.get("normal", {}))
    else:
        results = run_scenario(scenario)
        st.session_state.results = results
        st.session_state.all_results[scenario] = results

    st.session_state.logs = list(logger.logs)
    st.session_state.sim_status = "done"
    return results


# ─── Sidebar ─────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("# 🛡️ Control Panel")
    st.markdown("---")

    scenario = st.selectbox(
        "📡 Scenario",
        ["normal", "attack", "secure", "all"],
        format_func=lambda x: {
            "normal": "🟢 Normal Routing",
            "attack": "🔴 Sinkhole Attack",
            "secure": "🟡 Secure (Trust-Based)",
            "all": "📊 Run All (Compare)",
        }[x],
        index=0,
    )

    st.markdown("")

    if st.button("▶  RUN SIMULATION", use_container_width=True):
        with st.spinner("Running simulation..."):
            run_simulation_for_dashboard(scenario)
        st.rerun()

    st.markdown("---")

    # Status
    status_color = {"idle": "⚪", "done": "🟢"}
    st.markdown(f"**Status:** {status_color.get(st.session_state.sim_status, '⚪')} "
                f"{st.session_state.sim_status.upper()}")

    if st.session_state.logs:
        alert_count = sum(1 for l in st.session_state.logs if l["level"] == "ALERT")
        secure_count = sum(1 for l in st.session_state.logs if l["level"] == "SECURE")
        st.metric("Total Logs", len(st.session_state.logs))
        st.metric("⚠ Alerts", alert_count)
        st.metric("🛡 Secure Actions", secure_count)

    st.markdown("---")

    # Export
    if st.session_state.logs:
        df_export = pd.DataFrame(st.session_state.logs)
        csv_data = df_export.to_csv(index=False)
        st.download_button(
            "📥 Export Logs (CSV)",
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
st.markdown("# 🛡️ Secure RPL Routing Simulation")
st.markdown(
    '<p style="color:#888; font-size:0.85rem; margin-top:-10px;">'
    'Contiki-NG Inspired · IoT Network Security · Trust-Based Detection</p>',
    unsafe_allow_html=True,
)

# Pipeline Status Bar
if st.session_state.sim_status == "done":
    pipeline_html = """
    <div class="pipeline-bar">
        <span class="pipeline-step step-done">✅ Simulation</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-done">✅ Log Analysis</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-done">✅ Detection</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-done">✅ Dashboard</span>
    </div>
    """
else:
    pipeline_html = """
    <div class="pipeline-bar">
        <span class="pipeline-step step-pending">⏳ Simulation</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-pending">⏳ Log Analysis</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-pending">⏳ Detection</span>
        <span style="color:#555; align-self:center;">→</span>
        <span class="pipeline-step step-active">🔄 Awaiting Input</span>
    </div>
    """
st.markdown(pipeline_html, unsafe_allow_html=True)

# ─── No Data State ──────────────────────────────────────────────
if not st.session_state.results:
    st.markdown("""
    <div style="text-align:center; padding:80px 20px; color:#555;">
        <div style="font-size:4rem; margin-bottom:20px;">📡</div>
        <div style="font-size:1.3rem; color:#888; margin-bottom:12px;">No Simulation Data</div>
        <div style="font-size:0.85rem;">Select a scenario and click <strong style="color:#00d4aa;">RUN SIMULATION</strong> to begin</div>
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
left_col, right_col = st.columns([1, 1])

with left_col:
    st.markdown("### 📡 Network Topology")

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
            line=dict(color="rgba(0, 212, 170, 0.27)", width=2),
            showlegend=False,
            hoverinfo="skip",
        ))

    # Draw nodes
    for nid_key, ndata in nodes_data.items():
        nid = int(nid_key) if isinstance(nid_key, str) else nid_key
        pos = ndata.get("position", (0, 0))

        if ndata.get("is_root"):
            color, symbol, size = "#00d4aa", "diamond", 22
            label = f"Node {nid} (ROOT)"
        elif ndata.get("is_malicious"):
            color, symbol, size = "#ff4444", "x", 20
            label = f"Node {nid} (MALICIOUS)"
        elif ndata.get("flagged"):
            color, symbol, size = "#ffa500", "triangle-up", 18
            label = f"Node {nid} (FLAGGED)"
        else:
            color, symbol, size = "#00ff88", "circle", 16
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
        plot_bgcolor="#0a0a0a",
        paper_bgcolor="#0a0a0a",
        xaxis=dict(visible=False, range=[0, 630]),
        yaxis=dict(visible=False, range=[380, -20], autorange=False),
        height=420,
        margin=dict(l=10, r=10, t=10, b=10),
        hoverlabel=dict(
            bgcolor="#111111",
            font_color="#e0e0e0",
            font_size=12,
            font_family="JetBrains Mono",
        ),
    )

    # Legend
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers",
                             marker=dict(color="#00d4aa", size=10, symbol="diamond"),
                             name="Root Node"))
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers",
                             marker=dict(color="#00ff88", size=10),
                             name="Sensor Node"))
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers",
                             marker=dict(color="#ff4444", size=10, symbol="x"),
                             name="Malicious Node"))
    fig.add_trace(go.Scatter(x=[None], y=[None], mode="markers",
                             marker=dict(color="#ffa500", size=10, symbol="triangle-up"),
                             name="Flagged Node"))

    fig.update_layout(
        legend=dict(
            bgcolor="#0a0a0a",
            font=dict(color="#888", size=10, family="JetBrains Mono"),
            orientation="h",
            yanchor="bottom",
            y=-0.05,
            xanchor="center",
            x=0.5,
        )
    )

    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

with right_col:
    st.markdown("### 📋 Live Simulation Logs")

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

        icon = {"INFO": " ", "DEBUG": " ", "ALERT": "⚠", "SECURE": "🛡"}.get(level, " ")

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
st.markdown("### 🚨 Attack Detection & Trust Analysis")

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
                f'<div class="alert-box">⚠ <strong>{item["Node"]}</strong> — '
                f'{item["Reason"]} — Trust: {item["Trust Score"]}</div>',
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            '<div class="secure-box">🛡 No malicious nodes detected — network is healthy</div>',
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
                colors.append("#00ff88")
            elif t >= 0.4:
                colors.append("#ffd700")
            else:
                colors.append("#ff4444")

        fig_trust = go.Figure(go.Bar(
            y=df_trust["Node"],
            x=df_trust["Trust Score"],
            orientation="h",
            marker=dict(color=colors, line=dict(color="rgba(255, 255, 255, 0.07)", width=1)),
            text=[f"{t:.3f}" for t in df_trust["Trust Score"]],
            textposition="auto",
            textfont=dict(color="#0a0a0a", size=11, family="JetBrains Mono"),
            hovertemplate="<b>%{y}</b><br>Trust: %{x:.3f}<extra></extra>",
        ))

        # Threshold line
        fig_trust.add_vline(x=0.4, line=dict(color="rgba(255, 68, 68, 0.53)", width=2, dash="dash"),
                            annotation_text="Threshold", annotation_position="top right",
                            annotation_font=dict(color="#ff4444", size=10))

        fig_trust.update_layout(
            plot_bgcolor="#0a0a0a",
            paper_bgcolor="#0a0a0a",
            xaxis=dict(title="Trust Score", range=[0, 1.05], color="#888",
                       gridcolor="rgba(255, 255, 255, 0.03)", title_font=dict(size=11)),
            yaxis=dict(color="#888", autorange="reversed"),
            height=300,
            margin=dict(l=10, r=10, t=10, b=30),
            font=dict(family="JetBrains Mono"),
        )

        st.plotly_chart(fig_trust, use_container_width=True, config={"displayModeBar": False})

st.markdown("---")

# ─── Metrics Comparison ─────────────────────────────────────────
st.markdown("### 📊 Scenario Comparison — Metrics")

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
                    colors_pdr.append("#00ff88")
                elif p >= 50:
                    colors_pdr.append("#ffd700")
                else:
                    colors_pdr.append("#ff4444")

            fig_pdr = go.Figure(go.Bar(
                x=df_metrics["Scenario"],
                y=df_metrics["PDR (%)"],
                marker=dict(
                    color=colors_pdr,
                    line=dict(color="rgba(255, 255, 255, 0.07)", width=1),
                ),
                text=[f"{v}%" for v in df_metrics["PDR (%)"]],
                textposition="auto",
                textfont=dict(color="#0a0a0a", size=13, family="JetBrains Mono"),
            ))

            fig_pdr.update_layout(
                title=dict(text="Packet Delivery Ratio", font=dict(color="#00d4aa", size=14)),
                plot_bgcolor="#0a0a0a",
                paper_bgcolor="#0a0a0a",
                xaxis=dict(color="#888", title=""),
                yaxis=dict(color="#888", title="PDR (%)", range=[0, 105], gridcolor="rgba(255, 255, 255, 0.03)"),
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
                marker=dict(color="#00d4aa"),
                text=df_metrics["Packets Delivered"],
                textposition="auto",
                textfont=dict(color="#0a0a0a", size=11),
            ))
            fig_packets.add_trace(go.Bar(
                x=df_metrics["Scenario"],
                y=df_metrics["Packets Total"] - df_metrics["Packets Delivered"],
                name="Lost",
                marker=dict(color="rgba(255, 68, 68, 0.53)"),
                text=df_metrics["Packets Total"] - df_metrics["Packets Delivered"],
                textposition="auto",
                textfont=dict(color="#e0e0e0", size=11),
            ))

            fig_packets.update_layout(
                title=dict(text="Packets: Delivered vs Lost", font=dict(color="#00d4aa", size=14)),
                barmode="stack",
                plot_bgcolor="#0a0a0a",
                paper_bgcolor="#0a0a0a",
                xaxis=dict(color="#888", title=""),
                yaxis=dict(color="#888", title="Packets", gridcolor="rgba(255, 255, 255, 0.03)"),
                height=350,
                margin=dict(l=10, r=10, t=40, b=10),
                legend=dict(font=dict(color="#888", size=10), orientation="h",
                            yanchor="bottom", y=-0.15, xanchor="center", x=0.5),
                font=dict(family="JetBrains Mono"),
            )

            st.plotly_chart(fig_packets, use_container_width=True, config={"displayModeBar": False})

        # Summary table
        st.dataframe(df_metrics, use_container_width=True, hide_index=True)

else:
    st.info("💡 Run **'Run All (Compare)'** scenario to see side-by-side comparison of Normal vs Attack vs Secure.")

# ─── Footer ──────────────────────────────────────────────────────
st.markdown("---")
st.markdown(
    '<div style="text-align:center; color:#444; font-size:0.75rem; padding:20px;">'
    '🛡️ Secure RPL Routing Simulation v1.0 · Contiki-NG Inspired · IoT Security Research<br>'
    'Built with Streamlit + Plotly · Trust-Based Detection Engine'
    '</div>',
    unsafe_allow_html=True,
)
