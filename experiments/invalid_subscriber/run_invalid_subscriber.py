import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import signal
from experiments.benchmark import benchmark, load_config

BASE_DIR = Path(__file__).resolve().parents[2]

config = load_config(
    BASE_DIR / "systems" / "configs" / "invalid_subscriber.json"
)

benchmark(
    experiment_name=config["experiment_name"],
    ue_count=config["ue_count"],
    duration=config["duration"],
    startup_delay=config["startup_delay"]
)