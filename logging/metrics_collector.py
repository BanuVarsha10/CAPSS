import os
import csv

# -------------------------------------
# File Paths
# -------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CSV_FILE = os.path.join(BASE_DIR, "..", "datasets", "registration_dataset10.csv")

RESULTS_DIR = os.path.join(BASE_DIR, "..", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

OUTPUT_FILE = os.path.join(RESULTS_DIR, "metrics_report.txt")

# -------------------------------------
# Counters
# -------------------------------------

total_records = 0
successful_registrations = 0
authentication_success = 0
authentication_failure = 0

unique_ue = set()
unique_suci = set()

# -------------------------------------
# Read CSV
# -------------------------------------

with open(CSV_FILE, "r", encoding="utf-8") as file:

    reader = csv.DictReader(file)

    for row in reader:

        total_records += 1

        # Registration Success
        if row["Registration_Status"] == "Success":
            successful_registrations += 1

        # -------------------------------------
        # Authentication Metrics
        # -------------------------------------

        if row["Authentication_Result"] == "Failure":
            authentication_failure += 1

        elif row["Authentication_Result"] == "Success":
            authentication_success += 1

        elif (
            row["Authentication_Result"] == ""
            and row["Registration_Status"] == "Success"
        ):
            authentication_success += 1

        # -------------------------------------
        # Unique UE IDs
        # -------------------------------------

        if row["UE_ID"]:
            unique_ue.add(row["UE_ID"])

        # -------------------------------------
        # Unique SUCIs
        # -------------------------------------

        if row["SUCI"]:
            unique_suci.add(row["SUCI"])

# -------------------------------------
# Prepare Report
# -------------------------------------

report = f"""
========== Registration Metrics ==========

Total Registration Records : {total_records}
Successful Registrations   : {successful_registrations}
Authentication Successes   : {authentication_success}
Authentication Failures    : {authentication_failure}
Unique UE IDs              : {len(unique_ue)}
Unique SUCIs               : {len(unique_suci)}

==========================================
"""

# -------------------------------------
# Print to Terminal
# -------------------------------------

print(report)

# -------------------------------------
# Save to File
# -------------------------------------

with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
    file.write(report)

print(f"Metrics report saved to: {OUTPUT_FILE}")