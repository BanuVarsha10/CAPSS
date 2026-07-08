from pathlib import Path

from experiments.benchmark import benchmark
from experiments.benchmark import load_config

BASE_DIR = Path(__file__).resolve().parents[2]

config = load_config(
    BASE_DIR / "systems" / "configs" / "congestion.json"
)

benchmark(
    experiment_name=config["experiment_name"],
    ue_count=config["ue_count"]
)