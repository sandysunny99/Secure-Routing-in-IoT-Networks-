"""
Lightweight Logger for RPL Simulation
In-memory log store with colored terminal output and CSV export.
"""

import csv
import io
import os
import sys
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

# Force UTF-8 output on Windows to handle Unicode chars
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# ─── In-Memory Log Store ────────────────────────────────────────
logs = []

# ─── Color Map ──────────────────────────────────────────────────
COLORS = {
    "INFO":   Fore.GREEN,
    "DEBUG":  Fore.CYAN,
    "ALERT":  Fore.RED + Style.BRIGHT,
    "SECURE": Fore.YELLOW + Style.BRIGHT,
}

ICONS = {
    "INFO":   ">",
    "DEBUG":  "~",
    "ALERT":  "!!",
    "SECURE": "##",
}


def log(level: str, message: str, node_id: int = None, scenario: str = ""):
    """Append a structured log entry and print to terminal."""
    entry = {
        "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "level": level.upper(),
        "node_id": node_id,
        "message": message,
        "scenario": scenario,
    }
    logs.append(entry)
    _print(entry)
    return entry


def _print(entry: dict):
    """Print a single log entry with color formatting."""
    level = entry["level"]
    color = COLORS.get(level, "")
    icon = ICONS.get(level, "")
    ts = entry["timestamp"]
    node = f"Node {entry['node_id']:>2}" if entry["node_id"] is not None else "      "
    print(f"  {Fore.WHITE}{Style.DIM}[{ts}]{Style.RESET_ALL} "
          f"{color}[{level:<6}]{Style.RESET_ALL} "
          f"{Fore.WHITE}{Style.DIM}{node}{Style.RESET_ALL}  "
          f"{color}{icon} {entry['message']}{Style.RESET_ALL}")


def get_logs(level_filter: str = None, scenario_filter: str = None) -> list:
    """Return logs, optionally filtered by level and/or scenario."""
    result = logs
    if level_filter:
        result = [l for l in result if l["level"] == level_filter.upper()]
    if scenario_filter:
        result = [l for l in result if l["scenario"] == scenario_filter]
    return result


def clear():
    """Clear all logs."""
    logs.clear()


def export_csv(path: str = "results/simulation_logs.csv"):
    """Export logs to CSV file."""
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else "results", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "level", "node_id", "message", "scenario"])
        writer.writeheader()
        writer.writerows(logs)
    return path


def print_banner():
    """Print the project banner."""
    print()
    print(f"  {Fore.CYAN}{Style.BRIGHT}+==================================================================+{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.GREEN}{Style.BRIGHT}SECURE RPL ROUTING SIMULATION v1.0{Style.RESET_ALL}                            {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.WHITE}Contiki-NG Inspired - IoT Security Research{Style.RESET_ALL}                   {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}")
    print(f"  {Fore.CYAN}{Style.BRIGHT}+==================================================================+{Style.RESET_ALL}")
    print()


def print_scenario_header(name: str):
    """Print a scenario separator."""
    print()
    print(f"  {Fore.CYAN}{Style.BRIGHT}=== {name.upper()} {'=' * 46}{Style.RESET_ALL}")
    print()


def print_pipeline(steps: dict):
    """Print pipeline status. steps = {'name': 'done'|'active'|'pending'}"""
    icons = {"done": f"{Fore.GREEN}[OK]", "active": f"{Fore.YELLOW}[..]", "pending": f"{Fore.WHITE}{Style.DIM}[  ]"}
    parts = []
    for name, status in steps.items():
        parts.append(f"{icons.get(status, '[  ]')} {name}{Style.RESET_ALL}")
    print(f"  Pipeline: {' -> '.join(parts)}")
    print()


def print_summary_table(title: str, rows: list):
    """Print a simple ASCII summary table. rows = list of dicts."""
    if not rows:
        return
    print()
    print(f"  {Fore.CYAN}{Style.BRIGHT}+-- {title} {'-' * (55 - len(title))}+{Style.RESET_ALL}")

    headers = list(rows[0].keys())
    header_line = "  | " + " | ".join(f"{Fore.WHITE}{Style.BRIGHT}{h:>14}{Style.RESET_ALL}" for h in headers) + " |"
    print(header_line)
    print(f"  {Fore.CYAN}+{'-' * 60}+{Style.RESET_ALL}")

    for row in rows:
        vals = []
        for h in headers:
            v = row[h]
            if isinstance(v, float):
                if v < 0.4:
                    vals.append(f"{Fore.RED}{v:>14.2f}{Style.RESET_ALL}")
                elif v < 0.7:
                    vals.append(f"{Fore.YELLOW}{v:>14.2f}{Style.RESET_ALL}")
                else:
                    vals.append(f"{Fore.GREEN}{v:>14.2f}{Style.RESET_ALL}")
            else:
                vals.append(f"{Fore.WHITE}{str(v):>14}{Style.RESET_ALL}")
        print("  | " + " | ".join(vals) + " |")

    print(f"  {Fore.CYAN}{Style.BRIGHT}+{'-' * 60}+{Style.RESET_ALL}")
    print()
