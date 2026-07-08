from pathlib import Path

from experiments.benchmark import benchmark
from experiments.benchmark import load_config

BASE_DIR = Path(__file__).resolve().parent.parent

config = load_config(
    BASE_DIR / "systems" / "configs" / "multiple_ue.json"
)

config["experiment_name"] = "20_ues"
config["ue_count"] = 20

benchmark(
    experiment_name=config["experiment_name"],
    ue_count=config["ue_count"]
)