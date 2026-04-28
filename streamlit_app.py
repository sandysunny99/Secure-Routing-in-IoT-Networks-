"""Streamlit app entrypoint for Streamlit Cloud deployment.

Streamlit Cloud expects the entry point at the repository root.
This file executes the dashboard app by running it as a script via runpy,
which ensures all module-level Streamlit calls are executed correctly.
"""

import runpy
import os
import sys

# Ensure the project root is on the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Execute dashboard/app.py as __main__ so all top-level st.* calls run
runpy.run_path(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard", "app.py"),
    run_name="__main__",
)
