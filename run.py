"""
Secure RPL Routing Simulation — CLI Entry Point
Interactive menu to run scenarios with colored terminal output.
"""

import sys
import os

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from colorama import init, Fore, Style
init(autoreset=True)

from utils import logger
from core.simulation import run_scenario, run_all_scenarios


def print_menu():
    """Print the interactive menu."""
    print(f"""
  {Fore.CYAN}{Style.BRIGHT}+--------------------------------------------------+{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}         {Fore.WHITE}{Style.BRIGHT}SELECT SIMULATION SCENARIO{Style.RESET_ALL}              {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}+--------------------------------------------------+{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}                                                  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.GREEN}[1]{Style.RESET_ALL} Normal Routing                          {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.RED}[2]{Style.RESET_ALL} Sinkhole Attack                         {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.YELLOW}[3]{Style.RESET_ALL} Secure Routing (Trust-Based)            {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.CYAN}[4]{Style.RESET_ALL} Run All (Comparison)                    {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.MAGENTA}[5]{Style.RESET_ALL} Export Logs (CSV)                       {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.WHITE}{Style.DIM}[6]{Style.RESET_ALL}{Fore.WHITE}{Style.DIM} Launch Web Dashboard{Style.RESET_ALL}                    {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}   {Fore.WHITE}{Style.DIM}[0]{Style.RESET_ALL}{Fore.WHITE}{Style.DIM} Exit{Style.RESET_ALL}                                    {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}                                                  {Fore.CYAN}{Style.BRIGHT}|{Style.RESET_ALL}
  {Fore.CYAN}{Style.BRIGHT}+--------------------------------------------------+{Style.RESET_ALL}
""")


def launch_dashboard():
    """Launch the Streamlit dashboard."""
    dashboard_path = os.path.join(os.path.dirname(__file__), "dashboard", "app.py")
    print(f"\n  {Fore.CYAN}Launching dashboard...{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}{Style.DIM}Running: streamlit run {dashboard_path}{Style.RESET_ALL}\n")
    os.system(f"streamlit run \"{dashboard_path}\"")


def main():
    """Main entry point."""
    logger.print_banner()

    last_results = None

    while True:
        print_menu()
        try:
            choice = input(f"  {Fore.CYAN}▶ Enter choice: {Style.RESET_ALL}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {Fore.YELLOW}Exiting...{Style.RESET_ALL}\n")
            break

        if choice == "1":
            logger.clear()
            last_results = run_scenario("normal")

        elif choice == "2":
            logger.clear()
            last_results = run_scenario("attack")

        elif choice == "3":
            logger.clear()
            last_results = run_scenario("secure")

        elif choice == "4":
            logger.clear()
            last_results = run_all_scenarios()

        elif choice == "5":
            if not logger.logs:
                print(f"\n  {Fore.YELLOW}No logs to export. Run a scenario first.{Style.RESET_ALL}\n")
            else:
                results_dir = os.path.join(os.path.dirname(__file__), "results")
                os.makedirs(results_dir, exist_ok=True)
                path = logger.export_csv(os.path.join(results_dir, "simulation_logs.csv"))
                print(f"\n  {Fore.GREEN}✓ Logs exported to: {path}{Style.RESET_ALL}\n")

        elif choice == "6":
            launch_dashboard()

        elif choice == "0":
            print(f"\n  {Fore.CYAN}Goodbye! 👋{Style.RESET_ALL}\n")
            break

        else:
            print(f"\n  {Fore.RED}Invalid choice. Try again.{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()
