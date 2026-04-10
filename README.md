# 🛡️ Secure RPL Routing Simulation

**Contiki-NG Inspired · IoT Network Security · Trust-Based Detection**

A lightweight, demo-focused simulation of RPL (Routing Protocol for Low-Power and Lossy Networks) routing in IoT networks, featuring sinkhole attack simulation and trust-based detection with both terminal visualization and an interactive web dashboard.

---

## 📐 Architecture

```
┌──────────────────────────────────────────────────┐
│              run.py (CLI Entry Point)             │
│        Menu: Normal / Attack / Secure / All       │
└──────────┬───────────────────────────┬───────────┘
           │                           │
  ┌────────▼────────┐       ┌─────────▼──────────┐
  │  Terminal Logs   │       │  Streamlit Dashboard │
  │  (Colored CLI)   │       │  (Dark Theme + Plotly)│
  └────────┬────────┘       └─────────┬──────────┘
           │                           │
  ┌────────▼───────────────────────────▼──────────┐
  │              utils/logger.py                   │
  │         In-memory log store + CSV export       │
  └────────┬──────────────────────────────────────┘
           │
  ┌────────▼──────────────────────────────────────┐
  │   core/simulation.py  +  core/security.py     │
  │   8 nodes · Static RPL · Attack · Detection   │
  └───────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run Terminal Demo

```bash
python run.py
```

This opens an interactive menu:
- `[1]` Normal Routing
- `[2]` Sinkhole Attack
- `[3]` Secure Routing (Trust-Based)
- `[4]` Run All (Comparison)
- `[5]` Export Logs (CSV)
- `[6]` Launch Web Dashboard

### 3. Run Web Dashboard

```bash
streamlit run dashboard/app.py
```

Opens at `http://localhost:8501` with dark theme.

---

## 📁 Project Structure

```
├── run.py                    # CLI entry point
├── requirements.txt          # Dependencies (4 packages)
├── README.md                 # This file
│
├── core/
│   ├── simulation.py         # RPL network simulation
│   └── security.py           # Detection + trust + rerouting
│
├── dashboard/
│   └── app.py                # Streamlit web dashboard
│
├── utils/
│   └── logger.py             # Colored logging + export
│
├── .streamlit/
│   └── config.toml           # Dark theme config
│
├── docs/
│   └── contiki-guide.md      # Optional Contiki-NG reference
│
└── results/                  # Generated CSV exports
```

---

## 🧪 Simulation Scenarios

### 1. Normal Routing 🟢
- 8 nodes form DODAG via RPL
- All packets delivered to root
- Expected PDR: >95%

### 2. Sinkhole Attack 🔴
- Node 8 advertises fake rank (256) to attract traffic
- Drops 80% of forwarded packets
- Expected PDR: <50%

### 3. Secure Routing 🟡
- Trust-based detection identifies malicious node
- Traffic rerouted away from attacker
- Expected PDR: >80%

---

## 📊 Dashboard Features

| Panel | Description |
|-------|-------------|
| Pipeline Status | Animated workflow: Simulation → Logs → Detection → Dashboard |
| Network Topology | Interactive Plotly graph with colored nodes and edges |
| Live Logs | Scrollable, color-coded, filterable by level |
| Attack Detection | Flagged nodes table with reasons |
| Trust Scores | Horizontal bar chart with threshold line |
| Metrics Comparison | PDR charts comparing all scenarios |
| Export | CSV download of all logs |

---

## 🔧 Configuration

Edit constants at the top of `core/simulation.py`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `NUM_SENSORS` | 6 | Number of sensor nodes |
| `NUM_ROUNDS` | 20 | Packets per sensor per scenario |
| `ATTACK_DROP_RATE` | 0.80 | Packet drop probability |
| `FAKE_RANK` | 256 | Malicious node's fake rank |
| `DEMO_DELAY` | 0.08 | Seconds between log events |

---

## 🔮 Future Enhancements

- [ ] Machine learning-based anomaly detection
- [ ] Real-time Contiki-NG log ingestion via serial
- [ ] Multiple attack types (wormhole, selective forwarding)
- [ ] Energy consumption modeling
- [ ] MQTT/CoAP protocol integration

---

## 📚 References

- [Contiki-NG](https://github.com/contiki-ng/contiki-ng) — IoT operating system
- [RFC 6550](https://tools.ietf.org/html/rfc6550) — RPL specification
- [Cooja Simulator](https://docs.contiki-ng.org/en/develop/doc/tutorials/Cooja-simulations.html)

---

*Built for IoT Security Research · Demo-Focused · Lightweight*
