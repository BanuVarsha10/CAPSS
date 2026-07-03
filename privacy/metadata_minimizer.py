import os
import csv
from datetime import datetime

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

INPUT_FILE = os.path.join(
    BASE_DIR,
    "..",
    "datasets",
    "registration_dataset.csv"
)

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "..",
    "results"
)

os.makedirs(RESULTS_DIR, exist_ok=True)

OUTPUT_FILE = os.path.join(
    RESULTS_DIR,
    "anonymized_registration_dataset.csv"
)

# --------------------------------------------------
# Dictionaries for pseudonyms
# --------------------------------------------------

ue_map = {}
suci_map = {}

ue_counter = 1
suci_counter = 1

rows = []

first_timestamp = None

# --------------------------------------------------
# Read Dataset
# --------------------------------------------------

with open(INPUT_FILE, "r", encoding="utf-8") as file:

    reader = csv.DictReader(file)

    for row in reader:

        # ------------------------------------------
        # Convert Timestamp to Relative Time
        # ------------------------------------------

        if row["Timestamp"]:

            current_time = datetime.strptime(
                row["Timestamp"],
                "%m/%d %H:%M:%S.%f"
            )

            if first_timestamp is None:
                first_timestamp = current_time

            delta = current_time - first_timestamp

            row["Timestamp"] = f"T+{delta.total_seconds():.3f}s"

        # ------------------------------------------
        # Replace UE_ID
        # ------------------------------------------

        if row["UE_ID"]:

            if row["UE_ID"] not in ue_map:

                ue_map[row["UE_ID"]] = f"UE_{ue_counter:03}"

                ue_counter += 1

            row["UE_ID"] = ue_map[row["UE_ID"]]

        # ------------------------------------------
        # Replace SUCI
        # ------------------------------------------

        if row["SUCI"]:

            if row["SUCI"] not in suci_map:

                suci_map[row["SUCI"]] = f"SUCI_{suci_counter:03}"

                suci_counter += 1

            row["SUCI"] = suci_map[row["SUCI"]]

        # ------------------------------------------
        # Mask gNB IP
        # ------------------------------------------

        if row["gNB_IP"]:

            parts = row["gNB_IP"].split(".")

            if len(parts) == 4:

                row["gNB_IP"] = f"{parts[0]}.{parts[1]}.xxx.xxx"

        # ------------------------------------------
        # Generalize DNN
        # ------------------------------------------

        if row["DNN"]:

            row["DNN"] = "DEFAULT_DNN"

        # ------------------------------------------
        # Generalize S-NSSAI
        # ------------------------------------------

        if row["S_NSSAI"]:

            row["S_NSSAI"] = "DEFAULT_SLICE"

        rows.append(row)

# --------------------------------------------------
# Write Anonymized Dataset
# --------------------------------------------------

fieldnames = [
    "Timestamp",
    "Event",
    "UE_ID",
    "SUCI",
    "Authentication_Result",
    "Registration_Status",
    "gNB_IP",
    "DNN",
    "S_NSSAI"
]

with open(
    OUTPUT_FILE,
    "w",
    newline="",
    encoding="utf-8"
) as file:

    writer = csv.DictWriter(
        file,
        fieldnames=fieldnames
    )

    writer.writeheader()

    writer.writerows(rows)

print("\n======================================")
print("Metadata Minimization Completed")
print(f"Records Processed : {len(rows)}")
print(f"Output File       : {OUTPUT_FILE}")
print("======================================")