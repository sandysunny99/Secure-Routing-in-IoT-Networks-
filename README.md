# 🛡️ Secure RPL Routing Simulation

**Contiki-NG Inspired · IoT Network Security · Trust-Based Detection**

A lightweight Python simulation of RPL (Routing Protocol for Low-Power and Lossy Networks) routing in IoT networks. It demonstrates:

- Normal RPL routing
- Sinkhole attack behavior
- Trust-based secure rerouting
- Terminal visualization with color-coded logs
- Streamlit dashboard UI
- CSV export for logs

---

## 📦 Repository contents

- `run.py` — CLI entry point with interactive simulation menu
- `core/simulation.py` — main RPL simulation engine
- `core/security.py` — detection, trust scoring, and rerouting logic
- `dashboard/app.py` — Streamlit dashboard UI
- `utils/logger.py` — structured logging and CSV export
- `.streamlit/config.toml` — dashboard theme and server settings
- `requirements.txt` — required Python packages
- `launch.bat` — Windows Streamlit launcher
- `docs/contiki-guide.md` — optional Contiki-NG reference

---

## 🎯 Project purpose

This repository is a research/demo implementation of secure routing in an IoT network using RPL. It simulates routing behavior, models a sinkhole attack, and shows how trust-based detection can protect the network.

---

## ✅ Environment requirements

- Python 3.11+ (Windows compatible)
- `streamlit`
- `plotly`
- `pandas`
- `colorama`

---

## 🧪 Setup (Windows)

Open PowerShell in the project root and run:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

If `.venv` already exists, activate it instead:

```powershell
.venv\Scripts\activate
```

---

## ▶️ Running the project

### Terminal demo

```powershell
python run.py
```

The interactive menu includes:
- `1` Normal Routing
- `2` Sinkhole Attack
- `3` Secure Routing (Trust-Based)
- `4` Run All Scenarios
- `5` Export Logs to CSV
- `6` Launch Web Dashboard

### Streamlit dashboard

```powershell
streamlit run dashboard/app.py
```
For Streamlit Community Cloud deployment, use the root entrypoint:

```text
streamlit_app.py
```
Then open the dashboard in your browser at:

```text
http://localhost:8501
```

Or use the Windows launcher:

```powershell
launch.bat
```

---

## 📁 Folder structure

```
├── run.py
├── launch.bat
├── requirements.txt
├── README.md
├── .streamlit/
│   └── config.toml
├── core/
│   ├── simulation.py
│   └── security.py
├── dashboard/
│   └── app.py
├── utils/
│   └── logger.py
├── docs/
│   └── contiki-guide.md
└── results/
```

---

## 🧠 Key components

- `core/simulation.py`: constructs the RPL network topology, selects parents, forwards packets, and computes packet delivery ratio (PDR).
- `core/security.py`: performs rank anomaly detection, trust scoring, and secure rerouting.
- `dashboard/app.py`: provides the Streamlit dashboard with topology, logs, and metrics.
- `utils/logger.py`: logs events in memory and exports them to CSV.

---

## 🔧 Configuration

Adjust simulation settings in `core/simulation.py`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `NUM_SENSORS` | 6 | Number of sensor nodes |
| `NUM_ROUNDS` | 20 | Packets per sensor per scenario |
| `ATTACK_DROP_RATE` | 0.80 | Sinkhole drop probability |
| `FAKE_RANK` | 128 | Malicious node's fake advertised rank |
| `DEMO_DELAY` | 0.08 | Delay for log pacing |

---

## 📊 Tested validation

- Repository synced with `origin/master`.
- Latest remote changes pulled successfully.
- Python dependencies installed into `.venv`.
- Verified `run_scenario('normal')` executes successfully.
- Confirmed `streamlit`, `plotly`, `pandas`, and `colorama` import cleanly.

---

## 📌 Notes

- `.venv/` is a local Python environment and should not be committed.
- `results/` stores generated log exports.
- This project is a research-focused IoT security simulation, not a production system.

---

## 🚀 Future improvements

- Add machine learning-based anomaly detection
- Add more attack types (wormhole, selective forwarding)
- Integrate Contiki-NG or Cooja simulation logs
- Add MQTT/CoAP support

---

*Secure Routing in IoT Networks — ready to run locally on Windows.*
