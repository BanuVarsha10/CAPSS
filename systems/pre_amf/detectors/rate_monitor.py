"""
CAPSS - Context-Aware Privacy Protection and Scheme Selection

File:
    rate_monitor.py

Purpose
-------
Monitors UE registration frequency to detect
registration flooding attacks.

This detector analyses registration history but
does not modify the registration timestamps.
"""

from systems.pre_amf.attack_rules import (
    ATTACK_FLOOD,
    ATTACK_NONE,
    MAX_REGISTRATIONS_PER_WINDOW,
    REGISTRATION_WINDOW,
    FLOOD_SCORE,
    LOW_CONFIDENCE,
    HIGH_CONFIDENCE,
    NORMAL,
    MALICIOUS,
    MESSAGE_FLOOD,
)

from systems.pre_amf.models import (
    ValidationContext,
    DetectionResult,
)


class RateMonitor:
    """
    Detect excessive registration frequency.
    """

    def __init__(self):

        self.peak_rate = 0.0

    # ======================================================

    def detect(
        self,
        context: ValidationContext,
    ) -> DetectionResult:

        request = context.request

        history = context.history

        current_time = request.timestamp

        # ==================================================
        # Sliding Window
        # ==================================================

        history.timestamps = [

            timestamp

            for timestamp in history.timestamps

            if (current_time - timestamp)

            <= REGISTRATION_WINDOW

        ]

        current_count = len(history.timestamps)

        window_seconds = REGISTRATION_WINDOW.total_seconds()

        current_rate = current_count / window_seconds

        if current_rate > self.peak_rate:

            self.peak_rate = current_rate

        # ==================================================
        # Authentication Statistics
        # ==================================================

        if request.authentication_result == "Success":

            history.successful_attempts += 1

        else:

            history.failed_attempts += 1

        # ==================================================
        # Registration Flood
        # ==================================================

        if current_count >= MAX_REGISTRATIONS_PER_WINDOW:

            history.flood_count += 1

            history.last_attack = ATTACK_FLOOD

            return DetectionResult(

                detected=True,

                attack_type=ATTACK_FLOOD,

                confidence=HIGH_CONFIDENCE,

                severity=MALICIOUS,

                score=FLOOD_SCORE,

                message=MESSAGE_FLOOD,

                current_rate=current_rate,

                peak_rate=self.peak_rate,

                current_count=current_count,

                window_seconds=int(window_seconds)

            )

        # ==================================================
        # Normal Behaviour
        # ==================================================

        return DetectionResult(

            detected=False,

            attack_type=ATTACK_NONE,

            confidence=LOW_CONFIDENCE,

            severity=NORMAL,

            score=0,

            message=(
                f"Registration rate "
                f"{current_rate:.2f} req/s"
            ),

            current_rate=current_rate,

            peak_rate=self.peak_rate,

            current_count=current_count,

            window_seconds=int(window_seconds)

        )


# ==========================================================
# Convenience Function
# ==========================================================

def monitor_registration_rate(
    context: ValidationContext,
) -> DetectionResult:
    """
    Convenience wrapper.
    """

    monitor = RateMonitor()

    return monitor.detect(context)