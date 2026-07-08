import subprocess
import time
from pathlib import Path

UERANSIM = Path.home() / "5g-project" / "UERANSIM"

CONFIGS = UERANSIM / "config" / "generated"

NR_UE = UERANSIM / "build" / "nr-ue"
print("Authenticating sudo once...")
subprocess.run(["sudo", "-v"], check=True)

processes = []

print("=" * 60)
print("Launching Multiple UEs")
print("=" * 60)

for i in range(1, 11):

    cfg = CONFIGS / f"ue{i:03d}.yaml"

    print(f"Starting UE {i:02d} ({cfg.name})")

    p = subprocess.Popen([
        "sudo",
        "-n",
        str(NR_UE),
        "-c",
        str(cfg)
    ])

    processes.append(p)

    time.sleep(1)

print()
print(f"{len(processes)} UE processes launched.")
print("Leave this terminal running.")
print("Press Ctrl+C when experiment finishes.")

try:
    while True:
        time.sleep(1)

except KeyboardInterrupt:

    print("\nStopping UEs...")

    subprocess.run(["sudo", "pkill", "-f", "nr-ue"])

    print("Done.")