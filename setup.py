#!/usr/bin/env python3
"""
Setup script for AI Network Observer
For backward compatibility - pyproject.toml is the preferred configuration
"""

from setuptools import setup, find_packages

if __name__ == "__main__":
    setup(
        packages=find_packages(where=".", include=["src*"]),
        package_dir={"": "."},
    )
