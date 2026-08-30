"""Marker module for Google Cloud Buildpacks Python runtime detection.

The DAHCorp OpenBB Cloud Run service is started by the Procfile; this module
exists only so the Python buildpack recognizes the isolated cloudrun wrapper
as a Python application.
"""
