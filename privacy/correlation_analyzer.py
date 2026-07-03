import os
import csv
from collections import Counter

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CSV_FILE = os.path.join(
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

REPORT_FILE = os.path.join(
    RESULTS_DIR,
    "correlation_report.txt"
)

# --------------------------------------------------
# Read Dataset
# --------------------------------------------------

ue_ids = []
sucis = []

contains_real_identifier = False

with open(CSV_FILE, "r", encoding="utf-8") as file:

    reader = csv.DictReader(file)

    for row in reader:

        ue = row["UE_ID"].strip()
        suci = row["SUCI"].strip()

        if ue:
            ue_ids.append(ue)

            if ue.startswith("imsi-"):
                contains_real_identifier = True

        if suci:
            sucis.append(suci)

            if suci.startswith("suci-"):
                contains_real_identifier = True

# --------------------------------------------------
# Count Occurrences
# --------------------------------------------------

ue_counter = Counter(ue_ids)
suci_counter = Counter(sucis)

repeated_ue = sum(
    1 for count in ue_counter.values()
    if count > 1
)

repeated_suci = sum(
    1 for count in suci_counter.values()
    if count > 1
)

total_records = len(ue_ids)

# --------------------------------------------------
# Correlation Score
# --------------------------------------------------

if (len(ue_counter) + len(suci_counter)) == 0:
    correlation_score = 0
else:
    correlation_score = (
        (repeated_ue + repeated_suci)
        /
        (len(ue_counter) + len(suci_counter))
    ) * 100

# --------------------------------------------------
# Interpretation
# --------------------------------------------------

if contains_real_identifier:

    interpretation = (
        "Interpretation:\n"
        "Direct subscriber identifiers are present in the dataset.\n"
        "Repeated IMSI/SUCI values allow registrations to be linked,\n"
        "resulting in a high correlation risk. Metadata minimization\n"
        "is recommended before sharing or storing this dataset."
    )

else:

    interpretation = (
        "Interpretation:\n"
        "Direct identifiers have been removed through metadata minimization.\n"
        "Records remain linkable through persistent pseudonyms.\n"
        "This is intentional to preserve historical registration\n"
        "information required for CAPSS experience retrieval and\n"
        "future policy generation while protecting subscriber identities."
    )

# --------------------------------------------------
# Display
# --------------------------------------------------

print("\n========== Correlation Report ==========\n")

print(f"Total Records          : {total_records}")
print(f"Unique UE IDs          : {len(ue_counter)}")
print(f"Unique SUCIs           : {len(suci_counter)}")
print(f"Repeated UE IDs        : {repeated_ue}")
print(f"Repeated SUCIs         : {repeated_suci}")
print(f"Correlation Score (%)  : {correlation_score:.2f}")

print("\n" + interpretation)

# --------------------------------------------------
# Save Report
# --------------------------------------------------

with open(REPORT_FILE, "w", encoding="utf-8") as report:

    report.write("========== Correlation Report ==========\n\n")

    report.write(f"Total Records         : {total_records}\n")
    report.write(f"Unique UE IDs         : {len(ue_counter)}\n")
    report.write(f"Unique SUCIs          : {len(suci_counter)}\n")
    report.write(f"Repeated UE IDs       : {repeated_ue}\n")
    report.write(f"Repeated SUCIs        : {repeated_suci}\n")
    report.write(f"Correlation Score (%) : {correlation_score:.2f}\n\n")

    report.write(interpretation)

print("\nReport saved successfully!")
print(REPORT_FILE)