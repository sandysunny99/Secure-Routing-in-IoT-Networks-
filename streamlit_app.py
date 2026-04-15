"""Streamlit app entrypoint for repository deployment."""

# Streamlit Cloud and other deployment platforms often expect an app entrypoint
# at the repository root. Importing the dashboard module executes the Streamlit app.

from dashboard import app  # noqa: F401
