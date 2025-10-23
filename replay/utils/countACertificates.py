import json
import time
from pathlib import Path
from typing import Any, Dict, Tuple, Union

def getCurrentTimestamp32() -> int:
    seconds_since_epoch = int(time.time())

    # Constants aligned with the C++ implementation
    seconds_per_year = 365 * 24 * 60 * 60
    leap_seconds = 8 * 24 * 60 * 60
    epoch_difference_seconds = (34 * seconds_per_year) + leap_seconds

    tai_seconds_since_2004 = seconds_since_epoch - epoch_difference_seconds

    # Emulates the uint32_t cast from the C++ code (wrap modulo 2^32)
    return tai_seconds_since_2004 & 0xFFFFFFFF

def _define_dict(maxCertificates: int) -> Dict[str, Tuple[bool, bool]]:
    """Helper to define a dictionary with keys from 0 to maxCertificates-1 and values (False, False)."""
    return {str(i): (False, False) for i in range(maxCertificates)}


def _evaluate_certificate(certificate_data: Any, reference_time: int) -> Tuple[bool, bool]:
    """Return (is_valid_now, is_expired_or_invalid) for a certificate payload."""

    if not isinstance(certificate_data, dict):
        return False, True

    start = certificate_data.get("start")
    end = certificate_data.get("end")

    try:
        start = int(start)
        end = int(end)
    except (TypeError, ValueError):
        return False, True

    if start <= reference_time <= end:
        return True, False

    if reference_time > end:
        return False, True

    return False, False


def count_active_certificates(certificates_path: Union[str, Path] = "PKIManager/certificates/certificates.json", maxCertificates: int = 0) -> Dict[str, Tuple[bool, bool]]:
    """Cleanup expired certificates and report EC/AT validity per vehicle."""

    path = Path(certificates_path)
    if not path.exists():
        raise FileNotFoundError(f"Certificates file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as certificates_file:
            certificates = json.load(certificates_file)
    except json.JSONDecodeError:
        certificates = {}
    
    if not certificates:
        if maxCertificates > 0:
            return {key : (False, False) for key in range(maxCertificates)}
        else:
            raise ValueError("No MaxCertificates provided, and no certificates found.")
        

    now = getCurrentTimestamp32()
    validity_by_vehicle = _define_dict(maxCertificates) if maxCertificates > 0 else {}
    should_persist = False


    for vehicle_id, certificate_bundle in list(certificates.items()):
        if not isinstance(certificate_bundle, dict):
            validity_by_vehicle[vehicle_id] = (False, False)
            del certificates[vehicle_id]
            should_persist = True
            continue

        ec_data = certificate_bundle.get("EC")
        ec_valid, ec_expired = _evaluate_certificate(ec_data, now)

        if not ec_valid:
            validity_by_vehicle[vehicle_id] = (False, False)

            if ec_expired:
                removed = False

                if "EC" in certificate_bundle:
                    del certificate_bundle["EC"]
                    removed = True

                if "AT" in certificate_bundle:
                    del certificate_bundle["AT"]
                    removed = True

                if not certificate_bundle:
                    certificates.pop(vehicle_id, None)
                    removed = True

                if removed:
                    should_persist = True

            continue

        at_data = certificate_bundle.get("AT")
        at_valid, at_expired = _evaluate_certificate(at_data, now)
        validity_by_vehicle[vehicle_id] = (True, at_valid)

        if at_expired and "AT" in certificate_bundle:
            del certificate_bundle["AT"]
            should_persist = True

        if not certificate_bundle:
            del certificates[vehicle_id]
            should_persist = True

    if should_persist:
        with path.open("w", encoding="utf-8") as certificates_file:
            json.dump(certificates, certificates_file, indent=4)

    return validity_by_vehicle
