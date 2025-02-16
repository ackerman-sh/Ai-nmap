#!/bin/bash

# Installation script for Onion Keyword Search Tool

if [ ! -d "myenv" ]; then
    echo "[INFO] 'myenv' virtual environment not found. Creating one..."
    python3 -m venv myenv

    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to create virtual environment. Make sure Python 3 and venv are installed."
        exit 1
    fi

    echo "[INFO] 'myenv' virtual environment created successfully."
else
    echo "[INFO] 'myenv' virtual environment already exists. Skipping creation."
fi

echo "[INFO] Activating 'myenv' virtual environment..."
source myenv/bin/activate

if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to activate the virtual environment. Exiting..."
    exit 1
fi

echo "[INFO] Installing required dependencies from requirements.txt..."
pip install --upgrade pip
pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "[ERROR] Failed to install dependencies. Check requirements.txt for issues."
    deactivate
    exit 1
fi

echo "[INFO] All dependencies installed successfully. Installation script completed."
deactivate
echo "[INFO] 'myenv' environment is ready for use. Run 'source myenv/bin/activate' to activate it."

exit 0
