#!/bin/sh

# Uninstall any previous version.
pip uninstall ingatesdk

# Create the package.
python setup.py sdist bdist_wheel

# Install the package.
pip install --no-index --find-links=dist/ ingatesdk
