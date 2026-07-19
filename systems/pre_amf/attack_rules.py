"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    attack_rules.py

Purpose
-------
Central configuration file for the CAPSS Pre-AMF Security Layer.

All validators, detectors and classifiers should import
their thresholds, labels and constants from this file.

This file MUST NOT contain any processing logic.
"""

from datetime import timedelta

# ==========================================================
# Registration Behaviour Thresholds
# ==========================================================

# Sliding monitoring window
REGISTRATION_WINDOW = timedelta(seconds=30)

# Maximum registrations allowed inside the window
MAX_REGISTRATIONS_PER_WINDOW = 5

# Duplicate registration interval
DUPLICATE_INTERVAL = timedelta(seconds=10)

# Replay-like interval
REPLAY_INTERVAL = timedelta(seconds=2)

# Maximum failed authentications
MAX_FAILED_AUTHENTICATIONS = 3

# Maximum duplicate registrations
MAX_DUPLICATES = 3

# Maximum replay events
MAX_REPLAY_EVENTS = 2

# Maximum flood detections
MAX_FLOOD_EVENTS = 2


# ==========================================================
# Subscriber Validation
# ==========================================================

BLOCK_UNKNOWN_SUBSCRIBERS = True


# ==========================================================
# Required Registration Fields
# ==========================================================

REQUIRED_FIELDS = [

    "request_id",

    "timestamp",

    "ue_id",

    "suci",

    "event",

    "registration_status",

    "gnb_ip",
]


# ==========================================================
# Valid Registration Types
# ==========================================================

VALID_REGISTRATION_TYPES = {

    "INITIAL",

    "MOBILITY_UPDATE",

    "PERIODIC_UPDATE",

    "EMERGENCY",

}


# ==========================================================
# Authentication Results
# ==========================================================

VALID_AUTH_RESULTS = {

    "Success",

    "Failure",

}


# ==========================================================
# Registration Status
# ==========================================================

VALID_REGISTRATION_STATUS = {

    "Success",

    "Failure",

}


# ==========================================================
# Decision Labels
# ==========================================================

ALLOW = "ALLOW"

TAG = "TAG"

BLOCK = "BLOCK"


# ==========================================================
# Severity Labels
# ==========================================================

NORMAL = "NORMAL"

SUSPICIOUS = "SUSPICIOUS"

MALICIOUS = "MALICIOUS"


# ==========================================================
# Risk Levels
# ==========================================================

LOW = "LOW"

MEDIUM = "MEDIUM"

HIGH = "HIGH"


# ==========================================================
# Detection Confidence
# ==========================================================

LOW_CONFIDENCE = 0.40

MEDIUM_CONFIDENCE = 0.70

HIGH_CONFIDENCE = 0.90


# ==========================================================
# Attack Labels
# ==========================================================

ATTACK_NONE = "NONE"

ATTACK_DUPLICATE = "DUPLICATE_REGISTRATION"

ATTACK_REPEATED = "REPEATED_REGISTRATION"

ATTACK_REPLAY = "REPLAY"

ATTACK_FLOOD = "REGISTRATION_FLOOD"

ATTACK_INVALID_HEADER = "INVALID_HEADER"

ATTACK_INVALID_PARAMETER = "INVALID_PARAMETER"

ATTACK_INVALID_SUBSCRIBER = "INVALID_SUBSCRIBER"

ATTACK_UNKNOWN = "UNKNOWN"


# ==========================================================
# Cause Codes
# ==========================================================

CAUSE_SUCCESS = "SUCCESS"

CAUSE_AUTH_FAILURE = "AUTH_FAILURE"

CAUSE_UNKNOWN_SUBSCRIBER = "UNKNOWN_SUBSCRIBER"

CAUSE_INVALID_PARAMETER = "INVALID_PARAMETER"

CAUSE_INVALID_HEADER = "INVALID_HEADER"

CAUSE_DUPLICATE = "DUPLICATE"

CAUSE_REPEATED = "REPEATED_REGISTRATION"

CAUSE_REPLAY = "REPLAY"

CAUSE_FLOOD = "REGISTRATION_FLOOD"


# ==========================================================
# Validation Scores
# ==========================================================

HEADER_VALIDATION_SCORE = 100

PARAMETER_VALIDATION_SCORE = 100

SUBSCRIBER_VALIDATION_SCORE = 100


# ==========================================================
# Detection Scores
# ==========================================================

DUPLICATE_SCORE = 50

REPLAY_SCORE = 80

FLOOD_SCORE = 95

INVALID_SUBSCRIBER_SCORE = 100

INVALID_PARAMETER_SCORE = 90

INVALID_HEADER_SCORE = 100


# ==========================================================
# Rate Monitor Defaults
# ==========================================================

DEFAULT_WINDOW_SECONDS = 30


# ==========================================================
# Default Values
# ==========================================================

DEFAULT_ATTACK = ATTACK_NONE

DEFAULT_SEVERITY = NORMAL

DEFAULT_EXPERIMENT = "NORMAL"

DEFAULT_REGISTRATION_TYPE = "INITIAL"

DEFAULT_CAUSE_CODE = CAUSE_SUCCESS


# ==========================================================
# Default Messages
# ==========================================================

MESSAGE_VALID_REQUEST = (
    "Registration validated successfully."
)

MESSAGE_DUPLICATE = (
    "Duplicate registration detected."
)

MESSAGE_REPEATED = (
    "Repeated registration behaviour detected."
)

MESSAGE_REPLAY = (
    "Replay-like behaviour detected."
)

MESSAGE_FLOOD = (
    "Registration flooding detected."
)

MESSAGE_INVALID_SUBSCRIBER = (
    "Unknown subscriber detected."
)

MESSAGE_INVALID_PARAMETER = (
    "Invalid registration parameters."
)

MESSAGE_INVALID_HEADER = (
    "Invalid registration header."
)