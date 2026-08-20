#!/usr/bin/env bash

set -e

PYTHON_VERSION=${1:-"none"}

if [ "${PYTHON_VERSION}" = "none" ]; then
    echo "No Python version specified, skipping Python installation"
    exit 0
fi

# check if python${PYTHON_VERSION} is already installed
if python${PYTHON_VERSION} --version > /dev/null 2>&1; then
    echo "Python ${PYTHON_VERSION} is already installed"
    exit 0
fi

echo "Installing Python ${PYTHON_VERSION}"

# install python${PYTHON_VERSION}
sudo apt update
sudo apt install software-properties-common -y
sudo add-apt-repository ppa:deadsnakes/ppa -y
sudo apt install python${PYTHON_VERSION} -y
python${PYTHON_VERSION} --version
echo "Python ${PYTHON_VERSION} installed successfully"