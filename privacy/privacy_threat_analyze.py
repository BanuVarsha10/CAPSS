import os
import re

# --------------------------------------------------
# File Paths
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RESULTS_DIR = os.path.join(
    BASE_DIR,
    "..",
    "results"
)

os.makedirs(RESULTS_DIR, exist_ok=True)

PRIVACY_REPORT = os.path.join(
    RESULTS_DIR,
    "privacy_report.txt"
)

CORRELATION_REPORT = os.path.join(
    RESULTS_DIR,
    "correlation_report.txt"
)

OUTPUT_FILE = os.path.join(
    RESULTS_DIR,
    "privacy_threat_report.txt"
)

# --------------------------------------------------
# Small Parsing Helpers
# --------------------------------------------------
# NOTE: These helpers use flexible whitespace (\s*) around
# the ":" so they do not depend on exact column padding in
# the report files, unlike a plain substring match.

def extract_float(label, text, default=0.0):

    match = re.search(
        re.escape(label) + r"\s*:\s*([0-9.]+)",
        text
    )

    if match:
        return float(match.group(1))

    return default


def extract_int(label, text, default=0):

    match = re.search(
        re.escape(label) + r"\s*:\s*([0-9]+)",
        text
    )

    if match:
        return int(match.group(1))

    return default


def extract_str(label, text, default="N/A"):

    match = re.search(
        re.escape(label) + r"\s*:\s*(.+)",
        text
    )

    if match:
        return match.group(1).strip()

    return default


def extract_bool(label, text, default=False):

    match = re.search(
        re.escape(label) + r"\s*:\s*(YES|NO)",
        text
    )

    if match:
        return match.group(1) == "YES"

    return default


def extract_section(start_marker, end_marker, text):

    pattern = re.escape(start_marker) + r"(.*?)" + re.escape(end_marker)

    match = re.search(pattern, text, re.DOTALL)

    if match:
        return match.group(1)

    return ""


def risk_word_to_score(word):

    mapping = {
        "LOW": 20,
        "MEDIUM": 50,
        "HIGH": 80,
        "VERY HIGH": 100
    }

    return mapping.get((word or "").strip().upper(), 0)


def severity_from_confidence(confidence):

    if confidence >= 90:
        return "CRITICAL"

    if confidence >= 70:
        return "HIGH"

    if confidence >= 40:
        return "MEDIUM"

    return "LOW"


# --------------------------------------------------
# Variables
# --------------------------------------------------

privacy_score = 0
exposure_score = 0

privacy_overall_risk_score = 0.0

correlation_score = 0

max_registrations = 0

repeated_ue = False
repeated_suci = False
repeated_gnb = False
repeated_dnn = False
repeated_slice = False

threats = []

RECOMMENDATIONS = {
    "Linkability Risk": "Increase pseudonym rotation frequency",
    "Subscriber Tracking Risk": "Reduce metadata retention window",
    "Behaviour Profiling Risk": "Reduce service metadata retention (DNN/S-NSSAI)",
    "Metadata Correlation Risk": "Minimize stored identifiers across sessions",
    "Metadata Inference Risk": "Minimize exposed/stored identifiers",
    "Identity Disclosure Risk": "Strengthen identifier concealment (SUCI use, encryption)",
    "Membership Inference Risk": "Limit repeated participation visibility, aggregate records",
    "Registration Flood": "Enable rate limiting on registration requests",
    "Registration Retry Attack": "Enable rate limiting and investigate retry cause",
    "Authentication Abuse": "Temporarily throttle or monitor the affected UE",
    "Brute Force Authentication": "Lock out / rate-limit UE after repeated auth failures",
    "Mobility Tracking Risk": "Shorten location history retention",
    "Location Correlation Risk": "Shorten location history retention, generalize gNB records"
}

# Names that represent CONFIRMED active attack behaviour (only
# fire on real frequency/burst/failure evidence) vs. structural
# correlation-based privacy risk (fires on repeated identifiers,
# damped/labeled by the behaviour classification above).

ACTIVE_ATTACK_NAMES = {
    "Registration Flood",
    "Registration Retry Attack",
    "Brute Force Authentication",
    "Authentication Abuse",
    "Mobility Tracking Risk"
}

# --------------------------------------------------
# Read Privacy Report
# --------------------------------------------------

with open(PRIVACY_REPORT, "r", encoding="utf-8") as file:

    privacy_text = file.read()

match = re.search(
    r"Average Privacy Score\s*:\s*([0-9.]+)",
    privacy_text
)

if match:
    privacy_score = float(match.group(1))

match = re.search(
    r"Highest Exposure Score\s*:\s*([0-9.]+)",
    privacy_text
)

if match:
    exposure_score = float(match.group(1))

# --------------------------------------------------
# Read Privacy Report's Own Overall Risk Score (NEW)
# --------------------------------------------------
# The privacy report computes its own "Average Overall Risk
# Score" (from exposure/privacy alone, without correlation or
# behaviour evidence). This was previously parsed nowhere in
# this script, so this script's independently-derived
# "Overall Privacy Risk" could silently disagree with the
# privacy report's own verdict. It is now read in here so it
# can be cross-checked against this script's own assessment
# further down (see "Cross-Check Against Privacy Report's Own
# Overall Risk" below) - nothing else about how it's used
# elsewhere in this file has changed.

match = re.search(
    r"Average Overall Risk Score\s*:\s*([0-9.]+)",
    privacy_text
)

if match:
    privacy_overall_risk_score = float(match.group(1))

# --------------------------------------------------
# Read Correlation Report
# --------------------------------------------------

with open(CORRELATION_REPORT, "r", encoding="utf-8") as file:

    correlation_text = file.read()

match = re.search(
    r"Correlation Score\s*:\s*([0-9.]+)",
    correlation_text
)

if match:
    correlation_score = float(match.group(1))

match = re.search(
    r"Maximum Registrations / UE\s*:\s*([0-9.]+)",
    correlation_text
)

if match:
    max_registrations = int(float(match.group(1)))

repeated_ue = (
    "Repeated UE IDs                : YES"
    in correlation_text
)

repeated_suci = (
    "Repeated SUCIs                 : YES"
    in correlation_text
)

repeated_gnb = (
    "Repeated gNB                   : YES"
    in correlation_text
)

repeated_dnn = (
    "Repeated DNN                   : YES"
    in correlation_text
)

repeated_slice = (
    "Repeated S-NSSAI               : YES"
    in correlation_text
)

# --------------------------------------------------
# Read Correlation Report (Phase 2 Extended Fields)
# --------------------------------------------------
# Registration frequency / density

registration_duration_sec = extract_float(
    "Registration Duration (sec)", correlation_text
)

avg_registration_interval_sec = extract_float(
    "Average Registration Interval", correlation_text
)

min_registration_interval_sec = extract_float(
    "Minimum Registration Interval", correlation_text
)

max_registration_interval_sec = extract_float(
    "Maximum Registration Interval", correlation_text
)

registrations_per_minute = 0.0

if registration_duration_sec > 0:
    registrations_per_minute = (
        max_registrations / (registration_duration_sec / 60.0)
    )

registrations_per_hour = registrations_per_minute * 60.0

# Burst registration

burst_detected = extract_bool(
    "Burst Registration Detected", correlation_text
)

num_bursty_ues = extract_int(
    "Number of Bursty UEs", correlation_text
)

most_bursty_ue = extract_str(
    "Most Bursty UE", correlation_text
)

burst_registration_pattern = extract_bool(
    "Burst Registration Pattern", correlation_text
)

# Registration failures

total_reg_failures = extract_int(
    "Total Registration Failures", correlation_text
)

ues_with_reg_failures = extract_int(
    "UEs With Registration Failures", correlation_text
)

most_failed_ue = extract_str(
    "Most Failed UE", correlation_text
)

previous_failures_present = extract_bool(
    "Previous Failures Present", correlation_text
)

# Authentication failures

total_auth_failures = extract_int(
    "Total Auth Failures", correlation_text
)

total_auth_successes = extract_int(
    "Total Auth Successes", correlation_text
)

ues_with_auth_failures = extract_int(
    "UEs With Auth Failures", correlation_text
)

most_auth_failed_ue = extract_str(
    "Most Auth-Failed UE", correlation_text
)

auth_history_failures_present = extract_bool(
    "Auth History Failures Present", correlation_text
)

auth_total = total_auth_failures + total_auth_successes

auth_failure_rate = 0.0

if auth_total > 0:
    auth_failure_rate = (total_auth_failures / auth_total) * 100.0

# Lowest success rate UE, e.g:
# "imsi-999700000000001 (98.2% success)"

lowest_success_rate = 100.0
lowest_success_rate_ue = "N/A"

match = re.search(
    r"Lowest Success Rate UE\s*:\s*(.+?)\s*\(([0-9.]+)%",
    correlation_text
)

if match:
    lowest_success_rate_ue = match.group(1).strip()
    lowest_success_rate = float(match.group(2))

# Location history

most_mobile_ue = extract_str(
    "Most Mobile UE", correlation_text
)

max_unique_gnbs = extract_int(
    "Max Unique gNBs (single UE)", correlation_text
)

ues_with_repeated_location = extract_int(
    "UEs With Repeated Location", correlation_text
)

location_correlation_risk = extract_str(
    "Location Correlation Risk", correlation_text
)

location_history_correlation = extract_bool(
    "Location History Correlation", correlation_text
)

# --------------------------------------------------
# Failure Sequence Analysis
# --------------------------------------------------
# Scans "FAIL -> SUCCESS -> FAIL -> ..." chains per UE to
# find clustered/consecutive failures (a signature of
# brute-force / retry behaviour), rather than only using
# the raw failure count.

sequence_section = extract_section(
    "FAILURE SEQUENCES (Chronological)",
    "LOCATION HISTORY",
    correlation_text
)

max_consecutive_failures = 0
brute_force_ues = []

for line in sequence_section.splitlines():

    line = line.strip()

    if not line or ":" not in line:
        continue

    ue_id, _, seq_str = line.partition(":")

    steps = [step.strip() for step in seq_str.split("->")]

    current_run = 0
    ue_max_run = 0

    for step in steps:

        if step == "FAIL":
            current_run += 1
            ue_max_run = max(ue_max_run, current_run)

        else:
            current_run = 0

    if ue_max_run > max_consecutive_failures:
        max_consecutive_failures = ue_max_run

    if ue_max_run >= 3:
        brute_force_ues.append(ue_id.strip())

# --------------------------------------------------
# Multi-Factor Evidence Confidence Engine
# --------------------------------------------------
# Combines correlation, privacy, exposure, frequency,
# authentication history, success rate, burst pattern and
# location signals into one weighted confidence score,
# instead of a single threshold. Weights follow the
# evidence-fusion scheme: 30/20/15/10/10/5/5/5.
#
# NOTE: The specific per-signal normalization thresholds
# below (e.g. 10 registrations/min -> saturation) are a
# documented design choice, not a value taken from the
# reports, since the source data doesn't define them.

def compute_evidence_confidence():

    freq_score = min(100.0, registrations_per_minute * 10.0)

    auth_score = min(
        100.0,
        (total_auth_failures * 10.0) + (max_consecutive_failures * 15.0)
    )

    success_score = max(0.0, 100.0 - lowest_success_rate)

    if burst_detected:
        burst_score = 100.0
    else:
        burst_score = min(100.0, num_bursty_ues * 25.0)

    location_score = risk_word_to_score(location_correlation_risk)

    confidence = (
        (correlation_score * 0.30) +
        ((100.0 - privacy_score) * 0.20) +
        (exposure_score * 0.15) +
        (freq_score * 0.10) +
        (auth_score * 0.10) +
        (success_score * 0.05) +
        (burst_score * 0.05) +
        (location_score * 0.05)
    )

    return min(99, int(confidence))


evidence_confidence = compute_evidence_confidence()

# --------------------------------------------------
# Registration Behaviour Classification
# --------------------------------------------------
# This is the piece that distinguishes "55 registrations
# spread over a day" (Normal) from "55 registrations in two
# minutes with repeated failures" (Probable Attack). It is
# evaluated independently of the correlation-based privacy
# threats below, since persistent identifiers can create a
# privacy risk even when the traffic behaviour itself is
# normal.
#
# NOTE: The point thresholds here are a documented design
# choice for turning several weak signals into one category,
# not a formula taken from the source material.

behaviour_evidence_points = 0
behaviour_reasons = []

if burst_detected:
    behaviour_evidence_points += 2
    behaviour_reasons.append(
        f"Burst registration pattern detected ({num_bursty_ues} bursty UE(s), "
        f"most bursty: {most_bursty_ue})"
    )

if registrations_per_minute >= 5:
    behaviour_evidence_points += 2
    behaviour_reasons.append(
        f"High registration frequency: {registrations_per_minute:.2f} reg/min"
    )
elif registrations_per_minute >= 1:
    behaviour_evidence_points += 1
    behaviour_reasons.append(
        f"Moderate registration frequency: {registrations_per_minute:.2f} reg/min"
    )

if max_consecutive_failures >= 3:
    behaviour_evidence_points += 2
    behaviour_reasons.append(
        f"{max_consecutive_failures} consecutive authentication failures observed"
    )

if lowest_success_rate < 70:
    behaviour_evidence_points += 2
    behaviour_reasons.append(
        f"Low authentication success rate: {lowest_success_rate:.1f}% "
        f"({lowest_success_rate_ue})"
    )
elif lowest_success_rate < 90:
    behaviour_evidence_points += 1
    behaviour_reasons.append(
        f"Reduced authentication success rate: {lowest_success_rate:.1f}% "
        f"({lowest_success_rate_ue})"
    )

if total_auth_failures >= 5:
    behaviour_evidence_points += 1
    behaviour_reasons.append(
        f"{total_auth_failures} total authentication failures across "
        f"{ues_with_auth_failures} UE(s)"
    )

if total_reg_failures >= 5:
    behaviour_evidence_points += 1
    behaviour_reasons.append(
        f"{total_reg_failures} total registration failures across "
        f"{ues_with_reg_failures} UE(s)"
    )

if behaviour_evidence_points == 0:
    behaviour_classification = "Normal Behaviour"
    behaviour_reasons.append(
        f"{max_registrations} registration(s) spread over "
        f"{registration_duration_sec / 3600.0:.2f} hour(s) "
        f"({registrations_per_minute:.3f} reg/min), no burst pattern, "
        f"high authentication success rate"
    )

elif behaviour_evidence_points <= 2:
    behaviour_classification = "Suspicious Behaviour"

else:
    behaviour_classification = "Probable Attack"

# --------------------------------------------------
# Attack vs. Privacy-Risk Damping
# --------------------------------------------------
# IMPORTANT: correlation_score only measures whether the
# same UE/SUCI/gNB/DNN/S-NSSAI keep reappearing. It says
# nothing about frequency, so on its own it cannot tell
# "3-5 registrations from one UE" or "55 registrations
# spread across a day" apart from an actual attack - both
# produce the same high correlation score. That distinction
# has to come from the Registration Behaviour Classification
# above (frequency, burst, consecutive failures, success
# rate), so it is applied here as an explicit damping factor
# on confidence, and as an explicit verdict label, for every
# threat that is derived from correlation/privacy/exposure
# alone.
#
# NOTE: the specific multiplier values are a documented
# design choice (not derived from the reports) that encodes
# "repetition alone is a privacy exposure, not proof of an
# attack, unless frequency/failure behaviour backs it up."

BEHAVIOUR_MULTIPLIER = {
    "Normal Behaviour": 0.40,
    "Suspicious Behaviour": 0.70,
    "Probable Attack": 1.00
}

BEHAVIOUR_VERDICT = {
    "Normal Behaviour": "STRUCTURAL PRIVACY RISK — NOT AN ACTIVE ATTACK",
    "Suspicious Behaviour": "POSSIBLE ATTACK — EVIDENCE INSUFFICIENT TO CONFIRM",
    "Probable Attack": "ACTIVE ATTACK — CONFIRMED BY BEHAVIOUR EVIDENCE"
}

attack_multiplier = BEHAVIOUR_MULTIPLIER[behaviour_classification]
attack_verdict = BEHAVIOUR_VERDICT[behaviour_classification]


def damp(confidence):
    # Applies the behaviour-based multiplier and re-floors/
    # re-ceils the result so correlation-only threats cannot
    # claim "attack"-level confidence without frequency or
    # failure evidence to back it up.
    return max(1, min(99, int(confidence * attack_multiplier)))

# --------------------------------------------------
# Threat Detection
# --------------------------------------------------
# Structural / correlation-based privacy risks below still
# fire on repeated-identifier + correlation-score evidence
# (a persistent pseudonym is a privacy risk regardless of
# traffic volume). What changed vs. the threshold-only
# version: confidence is now the multi-factor evidence score
# instead of a 1-2 term formula, and each threat carries
# severity, evidence, affected UE and a recommendation.

# ==================================================
# Linkability Attack
# ==================================================

if correlation_score >= 70 and (
    repeated_ue or repeated_suci
):

    confidence = damp(evidence_confidence)

    threats.append({

        "name": "Linkability Risk",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": attack_verdict,

        "affected_ue": most_bursty_ue if most_bursty_ue != "N/A" else lowest_success_rate_ue,

        "reason": [

            f"Correlation Score = {correlation_score:.2f}%",

            f"Same UE observed {max_registrations} times",

            "Persistent UE/SUCI pseudonyms enable record linkage"

        ],

        "evidence": [

            f"Repeated UE IDs = {repeated_ue}, Repeated SUCIs = {repeated_suci}",

            f"Registration behaviour classified as: {behaviour_classification}"

        ]
    })

# ==================================================
# Subscriber Tracking Attack
# ==================================================

if correlation_score >= 70 and (
    repeated_ue and repeated_gnb
):

    confidence = damp(evidence_confidence)

    threats.append({

        "name": "Subscriber Tracking Risk",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": attack_verdict,

        "affected_ue": most_mobile_ue,

        "reason": [

            "Repeated UE registrations detected",

            "Same gNB reused repeatedly",

            "Historical movement/session tracking is possible"

        ],

        "evidence": [

            f"Max Unique gNBs (single UE) = {max_unique_gnbs}",

            f"UEs With Repeated Location = {ues_with_repeated_location}",

            f"Location Correlation Risk = {location_correlation_risk}"

        ]
    })

# ==================================================
# Behaviour Profiling Attack
# ==================================================

if correlation_score >= 70 and (
    repeated_dnn or repeated_slice
):

    confidence = damp(evidence_confidence)

    threats.append({

        "name": "Behaviour Profiling Risk",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": attack_verdict,

        "affected_ue": most_bursty_ue if most_bursty_ue != "N/A" else "N/A",

        "reason": [

            "Repeated service usage detected",

            "Repeated S-NSSAI / DNN usage",

            "Long-term behavioural patterns can be inferred"

        ],

        "evidence": [

            f"Repeated DNN = {repeated_dnn}, Repeated S-NSSAI = {repeated_slice}",

            f"Registration behaviour classified as: {behaviour_classification}"

        ]
    })

# ==================================================
# Metadata Correlation Attack
# ==================================================

if correlation_score >= 80:

    confidence = damp(evidence_confidence)

    threats.append({

        "name": "Metadata Correlation Risk",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": attack_verdict,

        "affected_ue": "Dataset-wide",

        "reason": [

            f"Correlation Score = {correlation_score:.2f}%",

            "Multiple metadata fields remain correlated",

            "Cross-session linkage is possible"

        ],

        "evidence": [

            f"Repeated UE/SUCI/gNB/DNN/S-NSSAI = "
            f"{repeated_ue}/{repeated_suci}/{repeated_gnb}/{repeated_dnn}/{repeated_slice}"

        ]
    })

# ==================================================
# Metadata Inference Attack
# ==================================================

if exposure_score >= 70:

    confidence = damp(evidence_confidence)

    threats.append({

        "name": "Metadata Inference Risk",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": attack_verdict,

        "affected_ue": "Dataset-wide",

        "reason": [

            f"Exposure Score = {exposure_score:.2f}",

            f"Privacy Score = {privacy_score:.2f}",

            "Sensitive metadata remains visible"

        ],

        "evidence": [

            f"Evidence-fusion confidence = {evidence_confidence}%"

        ]
    })

# ==================================================
# Identity Disclosure Attack
# ==================================================

if exposure_score >= 85 and privacy_score <= 20:

    confidence = damp(98)

    threats.append({

        "name": "Identity Disclosure Risk",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": attack_verdict,

        "affected_ue": "Dataset-wide",

        "reason": [

            "Privacy score is critically low",

            "Identifiers are highly exposed",

            "Subscriber identity disclosure is possible"

        ],

        "evidence": [

            f"Privacy Score = {privacy_score:.2f}, Exposure Score = {exposure_score:.2f}"

        ]
    })

# ==================================================
# Membership Inference Attack
# ==================================================

if correlation_score >= 60 and privacy_score < 50:

    confidence = damp(85)

    threats.append({

        "name": "Membership Inference Risk",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": attack_verdict,

        "affected_ue": "Dataset-wide",

        "reason": [

            "Repeated participation detected",

            "Correlation remains high",

            "Presence of a subscriber may be inferred"

        ],

        "evidence": [

            f"Correlation Score = {correlation_score:.2f}%, Privacy Score = {privacy_score:.2f}"

        ]
    })

# ==================================================
# Registration Flood
# ==================================================
# Frequency/burst based - NOT triggered by repetition alone.

if burst_detected or registrations_per_minute >= 5:

    confidence = min(
        99,
        int(
            (registrations_per_minute * 8) +
            (num_bursty_ues * 5) +
            (correlation_score * 0.2)
        )
    )

    threats.append({

        "name": "Registration Flood",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": "ACTIVE ATTACK — CONFIRMED BY BEHAVIOUR EVIDENCE",

        "affected_ue": most_bursty_ue,

        "reason": [

            f"Registration rate = {registrations_per_minute:.2f} reg/min "
            f"({registrations_per_hour:.1f} reg/hour)",

            f"Burst Registration Detected = {burst_detected}",

            "Sustained high-frequency registrations suggest flooding/DoS behaviour"

        ],

        "evidence": [

            f"Number of Bursty UEs = {num_bursty_ues}, Most Bursty UE = {most_bursty_ue}"

        ]
    })

# ==================================================
# Registration Retry Attack
# ==================================================
# Requires actual registration failures PLUS elevated
# frequency/burst - a low failure count spread over a long
# window is treated as normal, not an attack.

if total_reg_failures >= 5 and (
    burst_registration_pattern or registrations_per_minute >= 1
):

    confidence = min(
        99,
        int((total_reg_failures * 6) + (registrations_per_minute * 5))
    )

    threats.append({

        "name": "Registration Retry Attack",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": "ACTIVE ATTACK — CONFIRMED BY BEHAVIOUR EVIDENCE",

        "affected_ue": most_failed_ue,

        "reason": [

            f"Total Registration Failures = {total_reg_failures}",

            f"UEs With Registration Failures = {ues_with_reg_failures}",

            "Repeated registration retries detected alongside elevated frequency"

        ],

        "evidence": [

            f"Registration rate = {registrations_per_minute:.2f} reg/min"

        ]
    })

# ==================================================
# Brute Force Authentication
# ==================================================
# Requires a run of 3+ CONSECUTIVE failures for a UE, not
# just a nonzero total failure count.

if max_consecutive_failures >= 3:

    confidence = min(
        99,
        int(60 + (max_consecutive_failures * 8))
    )

    threats.append({

        "name": "Brute Force Authentication",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": "ACTIVE ATTACK — CONFIRMED BY BEHAVIOUR EVIDENCE",

        "affected_ue": ", ".join(brute_force_ues) if brute_force_ues else most_auth_failed_ue,

        "reason": [

            f"{max_consecutive_failures} consecutive authentication failures observed",

            "Consecutive failure pattern is characteristic of credential guessing",

            f"Overall authentication success rate remains {100 - auth_failure_rate:.1f}%"

        ],

        "evidence": [

            f"Total Auth Failures = {total_auth_failures}, "
            f"Total Auth Successes = {total_auth_successes}"

        ]
    })

# ==================================================
# Authentication Abuse
# ==================================================
# Elevated failure volume WITHOUT necessarily being a tight
# consecutive run - e.g. many isolated failures over time.
# Explicitly excludes the isolated single-failure case (this
# dataset's 1 failure / 54 successes does not qualify).

elif total_auth_failures >= 5 or auth_failure_rate >= 15:

    confidence = min(
        99,
        int((total_auth_failures * 4) + auth_failure_rate)
    )

    threats.append({

        "name": "Authentication Abuse",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": "ACTIVE ATTACK — CONFIRMED BY BEHAVIOUR EVIDENCE",

        "affected_ue": most_auth_failed_ue,

        "reason": [

            f"Total Auth Failures = {total_auth_failures} "
            f"(failure rate {auth_failure_rate:.1f}%)",

            f"UEs With Auth Failures = {ues_with_auth_failures}",

            "Failure volume exceeds what isolated/normal auth errors would produce"

        ],

        "evidence": [

            f"Lowest Success Rate UE = {lowest_success_rate_ue} "
            f"({lowest_success_rate:.1f}%)"

        ]
    })

# ==================================================
# Mobility Tracking Risk
# ==================================================
# Flags genuine multi-gNB movement correlation, separate
# from the single-gNB "Location Correlation Risk" case below.

if max_unique_gnbs >= 3 and location_history_correlation:

    confidence = min(
        99,
        int((max_unique_gnbs * 10) + risk_word_to_score(location_correlation_risk) * 0.3)
    )

    threats.append({

        "name": "Mobility Tracking Risk",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": "ACTIVE ATTACK — CONFIRMED BY BEHAVIOUR EVIDENCE",

        "affected_ue": most_mobile_ue,

        "reason": [

            f"Max Unique gNBs (single UE) = {max_unique_gnbs}",

            f"Most Mobile UE = {most_mobile_ue}",

            "Movement across multiple gNBs enables coarse-grained location tracking"

        ],

        "evidence": [

            f"Location Correlation Risk = {location_correlation_risk}"

        ]
    })

# ==================================================
# Location Correlation Risk
# ==================================================
# Single/few-gNB repeated-location case (as in this dataset)
# - a real privacy signal, but weaker than active mobility
# tracking, so it is reported separately with its own
# confidence weighting.

elif location_correlation_risk in ("MEDIUM", "HIGH", "VERY HIGH") and ues_with_repeated_location > 0:

    confidence = damp(risk_word_to_score(location_correlation_risk))

    threats.append({

        "name": "Location Correlation Risk",

        "confidence": confidence,

        "severity": severity_from_confidence(confidence),

        "verdict": attack_verdict,

        "affected_ue": most_mobile_ue,

        "reason": [

            f"Location Correlation Risk = {location_correlation_risk}",

            f"UEs With Repeated Location = {ues_with_repeated_location}",

            "Repeated registrations from the same gNB reveal a fixed approximate location"

        ],

        "evidence": [

            f"Max Unique gNBs (single UE) = {max_unique_gnbs}"

        ]
    })

# --------------------------------------------------
# Overall Risk Assessment
# --------------------------------------------------

if privacy_score >= 60:

    if correlation_score >= 80:
        overall_risk = "MEDIUM"

    elif correlation_score >= 50:
        overall_risk = "LOW"

    else:
        overall_risk = "LOW"

elif privacy_score >= 40:

    if correlation_score >= 80:
        overall_risk = "HIGH"

    elif correlation_score >= 50:
        overall_risk = "MEDIUM"

    else:
        overall_risk = "MEDIUM"

else:

    if correlation_score >= 80:
        overall_risk = "VERY HIGH"

    elif correlation_score >= 50:
        overall_risk = "HIGH"

    else:
        overall_risk = "HIGH"

# Behaviour classification can escalate (never de-escalate)
# the overall risk label, since active attack behaviour is
# strictly worse than a purely structural correlation risk.

RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "VERY HIGH"]

if behaviour_classification == "Probable Attack":

    current_index = RISK_ORDER.index(overall_risk)
    overall_risk = RISK_ORDER[min(current_index + 1, len(RISK_ORDER) - 1)]

# --------------------------------------------------
# Cross-Check Against Privacy Report's Own Overall Risk (NEW)
# --------------------------------------------------
# The privacy report computes its own "Average Overall Risk
# Score" independently (from exposure/privacy alone, without
# correlation or behaviour evidence). This script's overall_risk
# above is derived independently too, from privacy_score and
# correlation_score. Previously, the privacy report's own score
# was never read at all, so the two verdicts could silently
# disagree (e.g. this script saying HIGH while the privacy
# report says LOW) with no indication anywhere that they didn't
# match.
#
# It is converted to the same LOW/MEDIUM/HIGH/VERY HIGH scale
# using the same 40/60/80 cutoffs already used elsewhere in
# this pipeline (see Correlation Risk Level), and is only ever
# allowed to escalate - never de-escalate - this script's
# overall_risk, following the same escalate-only pattern
# already used for the behaviour classification above.

def score_to_risk_level(score):

    if score >= 80:
        return "VERY HIGH"

    if score >= 60:
        return "HIGH"

    if score >= 40:
        return "MEDIUM"

    return "LOW"


privacy_report_risk_level = score_to_risk_level(privacy_overall_risk_score)

current_index = RISK_ORDER.index(overall_risk)
privacy_report_index = RISK_ORDER.index(privacy_report_risk_level)

overall_risk = RISK_ORDER[max(current_index, privacy_report_index)]

# --------------------------------------------------
# Sort Threats by Confidence
# --------------------------------------------------

threats.sort(
    key=lambda threat: threat["confidence"],
    reverse=True
)

# --------------------------------------------------
# Build Report
# --------------------------------------------------

report = []

report.append("=========================================================")
report.append("        CAPSS PRIVACY THREAT ASSESSMENT")
report.append("=========================================================\n")

report.append(f"Overall Privacy Risk : {overall_risk}\n")

# --------------------------------------------------
# Registration Behaviour Classification
# --------------------------------------------------

report.append("---------------------------------------------------------")
report.append("REGISTRATION BEHAVIOUR CLASSIFICATION")
report.append("---------------------------------------------------------")

report.append(f"Classification : {behaviour_classification}")
report.append(f"Evidence Points : {behaviour_evidence_points}\n")

report.append(
    f"Registration Rate : {registrations_per_minute:.3f} reg/min "
    f"({registrations_per_hour:.2f} reg/hour)"
)
report.append(f"Burst Registration Detected : {burst_detected}")
report.append(f"Max Consecutive Auth Failures : {max_consecutive_failures}")
report.append(f"Lowest Auth Success Rate : {lowest_success_rate:.1f}% ({lowest_success_rate_ue})\n")

report.append("Basis")

for reason in behaviour_reasons:
    report.append(f" • {reason}")

report.append("")

# --------------------------------------------------
# Threats
# --------------------------------------------------
# Split into two buckets so the report never conflates
# "identifiers are being reused" with "an attack is
# happening" - the two questions the checklist asked us to
# be able to tell apart.

active_attacks = [t for t in threats if t["name"] in ACTIVE_ATTACK_NAMES]
structural_risks = [t for t in threats if t["name"] not in ACTIVE_ATTACK_NAMES]


def render_threat_block(report, index, threat):

    report.append("---------------------------------------------------------")

    report.append(f"Threat {index}\n")

    report.append(
        f"Most Probable Privacy Threat : {threat['name']}\n"
    )

    report.append(
        f"Confidence : {threat['confidence']}%"
    )

    report.append(
        f"Severity : {threat['severity']}"
    )

    report.append(
        f"Verdict : {threat['verdict']}"
    )

    report.append(
        f"Affected UE : {threat['affected_ue']}\n"
    )

    report.append("Reason")

    for reason in threat["reason"]:

        report.append(f" • {reason}")

    report.append("\nEvidence")

    for evidence_line in threat["evidence"]:

        report.append(f" • {evidence_line}")

    report.append(
        f"\nRecommendation : {RECOMMENDATIONS.get(threat['name'], 'Review and monitor')}"
    )

    report.append("")


report.append("=========================================================")
report.append(f"ATTACK STATUS : {attack_verdict}")
report.append("=========================================================\n")

report.append("---------------------------------------------------------")
report.append("SECTION A — ACTIVE ATTACK INDICATORS")
report.append("(Only fire on frequency / burst / consecutive-failure evidence)")
report.append("---------------------------------------------------------\n")

if len(active_attacks) == 0:

    report.append(
        "No active attack indicators detected. Registration frequency, "
        "burst pattern, and authentication failure behaviour are within "
        "normal parameters.\n"
    )

else:

    for index, threat in enumerate(active_attacks, start=1):
        render_threat_block(report, index, threat)

report.append("---------------------------------------------------------")
report.append("SECTION B — STRUCTURAL PRIVACY RISKS")
report.append("(Repeated-identifier exposure; confidence is damped when")
report.append(" behaviour is Normal, since repetition alone is not an attack)")
report.append("---------------------------------------------------------\n")

if len(structural_risks) == 0:

    report.append("No significant structural privacy risks detected.\n")

else:

    for index, threat in enumerate(structural_risks, start=1):
        render_threat_block(report, index, threat)

# --------------------------------------------------
# Console Output
# --------------------------------------------------

print()

for line in report:

    print(line)

# --------------------------------------------------
# Save Report
# --------------------------------------------------

with open(
    OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:

    for line in report:

        file.write(line + "\n")

# --------------------------------------------------
# Summary
# --------------------------------------------------

print("\n=========================================================")
print("Privacy Threat Report Generated Successfully")
print("=========================================================")

print(f"\nOutput File : {OUTPUT_FILE}")

print(f"\nOverall Risk       : {overall_risk}")
print(f"Behaviour           : {behaviour_classification}")
print(f"Attack Status       : {attack_verdict}")

print(f"\nActive Attack Indicators : {len(active_attacks)}")

if len(active_attacks) > 0:

    print("------------------------------")

    for threat in active_attacks:

        print(f"• {threat['name']} ({threat['confidence']}%, {threat['severity']})")

    print("------------------------------")

print(f"\nStructural Privacy Risks : {len(structural_risks)}")

if len(structural_risks) > 0:

    print("------------------------------")

    for threat in structural_risks:

        print(f"• {threat['name']} ({threat['confidence']}%, {threat['severity']})")

    print("------------------------------")

print("\nAssessment Complete.\n")