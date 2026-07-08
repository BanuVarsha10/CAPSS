from pathlib import Path
from experiments.benchmark import benchmark, load_config

BASE_DIR = Path(__file__).resolve().parents[2]

config = load_config(
    BASE_DIR / "systems" / "configs" / "multiple_ue.json"
)

benchmark(
    experiment_name=config["experiment_name"],
    ue_count=config["ue_count"],
    duration=config["duration"],
    startup_delay=config["startup_delay"]
)