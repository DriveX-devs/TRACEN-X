import json
import time
from pathlib import Path
from typing import Any, Dict, Tuple, Union

MAX_CERTIFICATES = 2
def getCurrentTimestamp32() -> int:
    seconds_since_epoch = int(time.time())

    # Costanti come nel C++
    seconds_per_year = 365 * 24 * 60 * 60
    leap_seconds = 8 * 24 * 60 * 60
    epoch_difference_seconds = (34 * seconds_per_year) + leap_seconds

    tai_seconds_since_2004 = seconds_since_epoch - epoch_difference_seconds

    # Emula il cast a uint32_t del C++ (wrap modulo 2^32)
    return tai_seconds_since_2004 & 0xFFFFFFFF


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


def count_active_certificates(certificates_path: Union[str, Path] = "PKIManager/certificates/certificates.json") -> Dict[str, Tuple[bool, bool]]:
    """Cleanup expired certificates and report EC/AT validity per vehicle."""

    path = Path(certificates_path)
    if not path.exists():
        raise FileNotFoundError(f"Certificates file not found: {path}")

    with path.open("r", encoding="utf-8") as certificates_file:
        certificates = json.load(certificates_file)
    
    if not certificates:
        return {key : (False, False) for key in range(MAX_CERTIFICATES)}
        

    now = getCurrentTimestamp32()
    validity_by_vehicle: Dict[str, Tuple[bool, bool]] = {}
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


if __name__ == "__main__":

    path = "/Users/giuseppe/Desktop/TRACENX/TRACEN-X/PKIManager/certificates/certificates.json"
    print(count_active_certificates(path))
