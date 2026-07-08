import os
import re
import csv

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_LOG = os.path.join(BASE_DIR, "raw_logs", "amf.log")

LOG_FILE = os.environ.get(
    "CAPSS_LOG_FILE",
    DEFAULT_LOG
)

OUTPUT_DIR = os.path.join(BASE_DIR, "..", "datasets")
os.makedirs(OUTPUT_DIR, exist_ok=True)

OUTPUT_FILE = os.path.join(OUTPUT_DIR, "registration_dataset.csv")

# --------------------------------------------------
# Regular Expressions
# --------------------------------------------------

timestamp_re = re.compile(r"^(\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)")

suci_re = re.compile(r"(suci-[^\]\s]+)", re.IGNORECASE)

imsi_re = re.compile(r"(imsi-\d+)", re.IGNORECASE)

ip_re = re.compile(r"accepted\[(.*?)\]")

dnn_re = re.compile(r"DNN\[([^\]]+)\]")

snssai_re = re.compile(r"S_NSSAI\[([^\]]+)\]")

# --------------------------------------------------
# Variables
# --------------------------------------------------

records = []

current = None

last_gnb_ip = ""

# --------------------------------------------------
# Read Log
# --------------------------------------------------

with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as file:

    for line in file:

        # -------------------------------
        # Save gNB IP
        # -------------------------------

        if "gNB-N2 accepted" in line:

            ip = ip_re.search(line)

            if ip:
                last_gnb_ip = ip.group(1)

        # -------------------------------
        # Start Registration
        # -------------------------------

        if "InitialUEMessage" in line:

            # Save previous registration
            if current is not None:
                records.append(current)

            ts = timestamp_re.search(line)

            current = {
                "Timestamp": ts.group(1) if ts else "",
                "Event": "Registration",
                "UE_ID": "",
                "SUCI": "",
                "Authentication_Result": "",
                "Registration_Status": "",
                "gNB_IP": last_gnb_ip,
                "DNN": "",
                "S_NSSAI": ""
            }

            continue

        if current is None:
            continue

        # -------------------------------
        # SUCI
        # -------------------------------

        suci = suci_re.search(line)

        if suci:
            current["SUCI"] = suci.group(1)

        # -------------------------------
        # IMSI
        # -------------------------------

        imsi = imsi_re.search(line)

        if imsi:
            current["UE_ID"] = imsi.group(1)

        # -------------------------------
        # Authentication
        # -------------------------------

        if "Authentication failure" in line:
            current["Authentication_Result"] = "Failure"

        if "Authentication successful" in line:
            current["Authentication_Result"] = "Success"

        # -------------------------------
        # Registration Complete
        # -------------------------------

        if "Registration complete" in line:
            current["Registration_Status"] = "Success"

        # -------------------------------
        # DNN
        # -------------------------------

        dnn = dnn_re.search(line)

        if dnn:
            current["DNN"] = dnn.group(1)

        # -------------------------------
        # Slice
        # -------------------------------

        snssai = snssai_re.search(line)

        if snssai:
            current["S_NSSAI"] = snssai.group(1)

# --------------------------------------------------
# Save Last Registration
# --------------------------------------------------

if current is not None:
    records.append(current)

# --------------------------------------------------
# Write CSV
# --------------------------------------------------

with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:

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

    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()

    writer.writerows(records)

print("----------------------------------------")
print("AMF Log Parsing Completed")
print(f"Registrations Found : {len(records)}")
print(f"CSV Saved : {OUTPUT_FILE}")
print("----------------------------------------")
