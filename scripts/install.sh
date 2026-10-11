#!/usr/bin/env bash
# ROGUEBYTE Installation & Launch Script for WSL2 (Ubuntu / Kali Linux)
# Usage: chmod +x scripts/install.sh && ./scripts/install.sh

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}==========================================================${NC}"
echo -e "${GREEN}     ROGUEBYTE // CYBERSECURITY WORKSTATION INSTALLER     ${NC}"
echo -e "${GREEN}             WSL2 (Ubuntu & Kali Linux Edition)           ${NC}"
echo -e "${GREEN}==========================================================${NC}"

# Anchor to the project root directory containing app.py
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/app.py" ]; then
    cd "${SCRIPT_DIR}"
elif [ -f "${SCRIPT_DIR}/../app.py" ]; then
    cd "${SCRIPT_DIR}/.."
fi

echo -e "${CYAN}[*] Working directory: $(pwd)${NC}"

# 1. Check Python
echo -e "\n${CYAN}[*] Checking Python environment...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${YELLOW}[!] Python 3 not found. Installing via apt...${NC}"
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-venv
fi

PYTHON_VER=$(python3 --version)
echo -e "${GREEN}[+] Found ${PYTHON_VER}${NC}"

# 2. Virtual Environment Setup
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo -e "${CYAN}[*] Creating Python virtual environment in ${VENV_DIR}...${NC}"
    python3 -m venv "$VENV_DIR" || {
        echo -e "${YELLOW}[!] Installing python3-venv...${NC}"
        sudo apt-get install -y python3-venv
        python3 -m venv "$VENV_DIR"
    }
fi

echo -e "${CYAN}[*] Activating virtual environment...${NC}"
source "${VENV_DIR}/bin/activate"

# 3. Upgrade pip and install dependencies
echo -e "${CYAN}[*] Installing dependencies from requirements.txt...${NC}"
pip install --upgrade pip
pip install -r requirements.txt
pip install -e .

# 4. Verify SQLite Database
echo -e "${CYAN}[*] Verifying database schema...${NC}"
python3 -c "import app; from roguebyte.database.db import get_db; db = get_db(); print('SQLite schema verified.')"

# 5. Run test suite
echo -e "${CYAN}[*] Running test suite...${NC}"
PYTHONPATH=. python3 -m unittest tests/test_all.py || PYTHONPATH=. python3 -m unittest roguebyte/tests/test_all.py

# 6. Launch Application
echo -e "\n${GREEN}[+] Setup complete! Starting ROGUEBYTE...${NC}"
if [ -n "$DISPLAY" ] || [ -n "$WAYLAND_DISPLAY" ]; then
    echo -e "${CYAN}[*] Display detected. Launching PySide6 Desktop GUI...${NC}"
    python3 app.py
else
    echo -e "${YELLOW}[!] No graphical DISPLAY detected (headless WSL).${NC}"
    echo -e "${CYAN}[*] Launching local API mode on http://127.0.0.1:8765...${NC}"
    python3 app.py --api
fi
