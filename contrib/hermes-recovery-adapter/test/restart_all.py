"""Restart every component of the test instance mid-scenario: Gatekeeper
(state kept), the Hermes gateway, and the adapter sidecar."""

import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
GK = os.environ.get("GK_CHECKOUT", r"C:\Users\David\Documents\gatekeeper-recovery")

subprocess.run(["powershell", "-NoProfile", "-Command",
                "$p=(Get-NetTCPConnection -LocalPort 18780 -State Listen -EA SilentlyContinue).OwningProcess"
                "|Select -Unique; if($p){Stop-Process -Id $p -Force -Confirm:$false}"], check=False)
print("gatekeeper stopped", flush=True)
subprocess.run(["docker", "restart", "hermes-test"], check=True)
subprocess.run(["docker", "restart", "hermes-test-adapter"], check=True)
print("hermes gateway and sidecar restarted", flush=True)
log = open(os.path.join(HERE, "out", "gk.log"), "a")
subprocess.Popen([sys.executable, os.path.join(HERE, "gk_serve.py"), GK, "--keep"], stdout=log, stderr=log)
time.sleep(8)
print("gatekeeper restarted with its state", flush=True)
