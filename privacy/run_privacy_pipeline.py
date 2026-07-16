import os
import subprocess
import sys
import time

# --------------------------------------------------
# Base Directories
# --------------------------------------------------

PRIVACY_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(PRIVACY_DIR)

LOGGING_DIR = os.path.join(PROJECT_DIR, "logging")

# --------------------------------------------------
# Scripts to Execute
# --------------------------------------------------

PIPELINE = [

    # -----------------------------
    # Logging
    # -----------------------------

    ("Logging", os.path.join(LOGGING_DIR, "metrics_collector.py")),

    ("Logging", os.path.join(LOGGING_DIR, "registration_logger.py")),

    # -----------------------------
    # Privacy Analysis
    # -----------------------------

    ("Privacy", os.path.join(PRIVACY_DIR, "privacy_score.py")),

    ("Privacy", os.path.join(PRIVACY_DIR, "metadata_minimizer.py")),

    ("Privacy", os.path.join(PRIVACY_DIR, "correlation_analyzer.py")),

    # -----------------------------
    # Threat Analysis
    # -----------------------------

    ("Privacy", os.path.join(PRIVACY_DIR, "privacy_threat_analyze.py")),

    # -----------------------------
    # Final Summary
    # -----------------------------

    ("Privacy", os.path.join(PRIVACY_DIR, "privacy_summary.py")),

    # -----------------------------
    # Graphs
    # -----------------------------

    ("Privacy", os.path.join(PRIVACY_DIR, "generate_privacy_graphs.py"))

]

# --------------------------------------------------
# Banner
# --------------------------------------------------

print("\n======================================================")
print("              CAPSS PRIVACY PIPELINE")
print("======================================================\n")

start_time = time.time()

# --------------------------------------------------
# Execute Pipeline
# --------------------------------------------------

for index, (module, script) in enumerate(PIPELINE, start=1):

    print(f"[{index}/{len(PIPELINE)}] {module}")
    print(f"Running : {os.path.basename(script)}")

    result = subprocess.run(
        [sys.executable, script]
    )

    if result.returncode != 0:

        print("\nERROR")
        print(f"{os.path.basename(script)} failed.")

        sys.exit(result.returncode)

    print("Completed Successfully.\n")

# --------------------------------------------------
# Finish
# --------------------------------------------------

end_time = time.time()

print("======================================================")
print("     CAPSS Privacy Pipeline Completed Successfully")
print("======================================================")

print(f"\nExecution Time : {end_time - start_time:.2f} seconds\n")

# --------------------------------------------------
# Generated Outputs
# --------------------------------------------------

print("Generated Outputs")
print("--------------------------------------------------")

outputs = [

    # Logging

    "results/metrics_report.txt",

    "results/registration_summary.txt",

    # Privacy

    "results/privacy_report.txt",

    "results/anonymized_registration_dataset.csv",

    "results/correlation_report.txt",

    # Threat Analysis

    "results/privacy_threat_report.txt",

    # Final Report

    "results/privacy_summary.txt",

    # Graphs

    "results/graphs/privacy_score_distribution.png",

    "results/graphs/exposure_distribution.png",

    "results/graphs/identifier_statistics.png",

    "results/graphs/registration_statistics.png"

]

for file in outputs:

    print(f"✓ {file}")

print("--------------------------------------------------")

print("\nPipeline Finished Successfully.\n")