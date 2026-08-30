"""Cloud Run buildpack marker for the DAHCorp OpenBB service.

The runtime entrypoint is defined in Procfile and starts OpenBB's REST API.
This file exists so Google Cloud's Python buildpack detects the wrapper as a
Python application and installs requirements.txt.
"""
