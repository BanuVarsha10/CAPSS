import csv
import json
import subprocess
import time
import shutil
from pathlib import Path
from datetime import datetime

# --------------------------------------------------
# Paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

SYSTEMS = BASE_DIR / "systems" / "scripts"
LOGGING = BASE_DIR / "logging"

RAW_LOG = LOGGING / "raw_logs" / "amf.log"

RESULTS = BASE_DIR / "results"
ARCHIVE = RESULTS / "logs" / "archive"

# --------------------------------------------------
# Helper Functions
# --------------------------------------------------

def run(cmd):
    print(f"\n>>> {' '.join(cmd)}")
    subprocess.run(cmd, check=True)


def archive_previous_log():
    """
    Archive the previous experiment log and clear the local copy.
    """

    ARCHIVE.mkdir(parents=True, exist_ok=True)

    if RAW_LOG.exists() and RAW_LOG.stat().st_size > 0:

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        shutil.copy(
            RAW_LOG,
            ARCHIVE / f"amf_{timestamp}.log"
        )

        print("[OK] Previous AMF log archived.")

    # Always start with an empty local log
    RAW_LOG.parent.mkdir(parents=True, exist_ok=True)
    RAW_LOG.write_text("")


def create_result_folder(experiment_name):
    """
    Create results/<experiment>/experiment_<timestamp>
    """

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    folder = (
        RESULTS
        / experiment_name
        / f"experiment_{timestamp}"
    )

    folder.mkdir(parents=True, exist_ok=True)

    return folder


def save_results(result_folder):
    """
    Copy generated outputs into experiment folder.
    """

    files = [

        BASE_DIR / "datasets" / "registration_dataset.csv",

        BASE_DIR / "datasets" / "attack_dataset.csv",

        BASE_DIR / "results" / "registration_summary.txt",

        BASE_DIR / "results" / "metrics_report.txt",

        BASE_DIR / "logging" / "raw_logs" / "amf.log"

   ]

    for file in files:

        if file.exists():

            shutil.copy(
                file,
                result_folder / file.name
            )


def save_metadata(
    result_folder,
    experiment_name,
    ue_count,
    duration_setting,
    start_time,
    end_time
):

    metadata = result_folder / "metadata.txt"

    duration = end_time - start_time

    with open(metadata, "w") as f:

        f.write("CAPSS Experiment Metadata\n")
        f.write("=" * 40 + "\n\n")

        f.write(f"Experiment Name : {experiment_name}\n")
        f.write(f"UE Count        : {ue_count}\n")
        f.write(f"Configured Time : {duration_setting} sec\n")
        f.write(f"Start Time      : {start_time}\n")
        f.write(f"End Time        : {end_time}\n")
        f.write(f"Duration        : {duration}\n")

def update_summary_table(
    experiment_name,
    ue_count,
    start_time,
    end_time,
    result_folder
):
    """
    Append experiment information to summary table.
    """

    tables = RESULTS / "tables"
    tables.mkdir(parents=True, exist_ok=True)

    summary = tables / "experiment_summary.csv"

    duration = end_time - start_time

    write_header = (
       not summary.exists()
       or summary.stat().st_size == 0
    )

    with open(summary, "a", newline="") as f:

        writer = csv.writer(f)

        if write_header:
            writer.writerow([
                "Experiment",
                "UE Count",
                "Start Time",
                "End Time",
                "Duration",
                "Result Folder"
            ])

        writer.writerow([
            experiment_name,
            ue_count,
            start_time,
            end_time,
            duration,
            result_folder
        ])

def load_config(config_path):
    """
    Load experiment configuration from JSON.
    """

    with open(config_path, "r") as f:
        return json.load(f)

# --------------------------------------------------
# Benchmark Engine
# --------------------------------------------------

def benchmark(
    experiment_name="single_ue",
    ue_count=1,
    duration=30,
    startup_delay=5
):

    experiment_start = datetime.now()

    result_folder = create_result_folder(experiment_name)

    print("=" * 60)
    print(f"Running Experiment : {experiment_name}")
    print("=" * 60)

    print(f"Results Folder : {result_folder}")

    archive_previous_log()
    print("\nClearing Open5GS AMF log...")

    run([
        "sudo",
        "truncate",
        "-s",
        "0",
        "/var/log/open5gs/amf.log"
    ])
    # --------------------------------------------------

    run(["bash", str(SYSTEMS / "cleanup.sh")])

    run(["bash", str(SYSTEMS / "start_core.sh")])

    print(f"Waiting {startup_delay}s for Open5GS...")
    time.sleep(startup_delay)

    run(["bash", str(SYSTEMS / "check_core.sh")])

    # --------------------------------------------------

    print("\nStart gNB in another terminal:")

    print(f"bash {SYSTEMS/'start_gnb.sh'}")

    input("\nPress ENTER after gNB starts...")

    # --------------------------------------------------

    # --------------------------------------------------
    if experiment_name == "duplicate_attack":

        print("\nStart Duplicate Attack:")
        print(f"python3 {SYSTEMS/'start_duplicate_attack.py'}")
        input("\nPress ENTER after attack completes...")

    elif experiment_name == "registration_flood":

        print("\nStart Registration Flood:")
        print(f"python3 {SYSTEMS/'start_registration_flood.py'}")
        input("\nPress ENTER after attack completes...")
    
    elif experiment_name == "invalid_subscriber":

        print("\nStart Invalid Subscriber Attack:")
        print(f"python3 {SYSTEMS/'start_invalid_subscriber.py'}")
        input("\nPress ENTER after attack completes...")
    
    elif experiment_name == "mixed_traffic":

        print()

        print("=" * 60)

        print("Mixed Traffic Scenario")

        print("=" * 60)

        # ------------------------------------------
        # Step 1
        # ------------------------------------------

        print("\nSTEP 1")

        print("Start 2 Normal UEs")

        print(
            f"python3 {SYSTEMS/'start_multiple_ues.py'} --count 2"
        )

        input("\nPress ENTER after normal traffic completes...")

        # ------------------------------------------
        # Step 2
        # ------------------------------------------

        print("\nSTEP 2")

        print("Start Duplicate Registration Attack")

        print(
            f"python3 {SYSTEMS/'start_duplicate_attack.py'}"
        )

        input("\nPress ENTER after duplicate attack completes...")

        # ------------------------------------------
        # Step 3
        # ------------------------------------------

        print("\nSTEP 3")

        print("Start Invalid Subscriber Attack")

        print(
            f"python3 {SYSTEMS/'start_invalid_subscriber.py'}"
        )

        input("\nPress ENTER after invalid subscriber attack completes...")

    else:

        print("\nStart UE(s) in another terminal:")
        print(f"python3 {SYSTEMS/'start_multiple_ues.py'}")
        input("\nPress ENTER after registrations succeed...")

    if experiment_name != "mixed_traffic":

        input("\nPress ENTER after all UE registrations succeed...")

# --------------------------------------------------

    # --------------------------------------------------

    print("\nCollecting Open5GS logs...")

    run([
        "bash",
        str(BASE_DIR / "open5gs" / "scripts" / "collect_logs.sh")
    ])

    # --------------------------------------------------

    print("\nParsing logs...")

    run([
        "python3",
        str(LOGGING / "parse_amf_logs.py")
    ])

    run([
        "python3",
        str(LOGGING / "registration_logger.py")
    ])

    run([
        "python3",
        str(LOGGING / "metrics_collector.py")
    ])
    
    # --------------------------------------------------
    # Run CAPSS Pre-AMF Security Layer
    # --------------------------------------------------

    print("\nRunning CAPSS Pre-AMF Security Layer...")

    run([
        "python3",
        str(BASE_DIR / "systems" / "attacks" / "attack_runner.py")
    ])
    # --------------------------------------------------

    save_results(result_folder)

    experiment_end = datetime.now()

    save_metadata(
        result_folder,
        experiment_name,
        ue_count,
        duration,
        experiment_start,
        experiment_end
  )
    update_summary_table(
        experiment_name,
        ue_count,
        experiment_start,
        experiment_end,
        result_folder
    )

    duration = experiment_end - experiment_start

    print("\n" + "=" * 60)
    print("Experiment Completed Successfully")
    print("=" * 60)

    print(f"Experiment : {experiment_name}")
    print(f"UE Count   : {ue_count}")
    print(f"Duration   : {duration}")
    print(f"Results    : {result_folder}")


# --------------------------------------------------

if __name__ == "__main__":

    config = load_config(
        BASE_DIR / "systems" / "configs" / "single_ue.json"
    )

    benchmark(
        experiment_name=config["experiment_name"],
        ue_count=config["ue_count"]
    )
