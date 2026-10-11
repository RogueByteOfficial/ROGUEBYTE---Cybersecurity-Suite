"""
ROGUEBYTE Windows Executable Packaging Script (PyInstaller)
Compiles ROGUEBYTE into a standalone Windows binary (.exe) or directory distribution.
"""

import os
import sys
import subprocess

def build():
    print("[*] Preparing PyInstaller build for ROGUEBYTE...")
    spec_file = os.path.join(os.path.dirname(__file__), "..", "roguebyte.spec")

    if not os.path.exists(spec_file):
        print(f"[!] Error: Spec file not found at {spec_file}")
        return 1

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        spec_file
    ]

    print(f"[*] Executing: {' '.join(cmd)}")
    res = subprocess.run(cmd)
    if res.returncode == 0:
        print("\n[+] Build succeeded! Executable located in dist/ROGUEBYTE/ or dist/ROGUEBYTE.exe")
    else:
        print("\n[!] Build failed. Ensure PyInstaller is installed: pip install pyinstaller")
    return res.returncode

if __name__ == "__main__":
    sys.exit(build())
