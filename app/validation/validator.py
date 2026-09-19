"""
Validation Engine for ULPF.
Executes schema validation, boundary checks, data type constraints,
and cryptographic verification on Universal Events using Pydantic.
"""

from typing import Dict, Any, Tuple, Optional
import ipaddress
from pydantic import ValidationError as PydanticValidationError

from app.models.universal_event import UniversalEvent
from app.models.errors import ValidationError
from app.integrity.hashing import verify_sha256


class Validator:
    """
    Validates that a constructed Universal Event dictionary complies with
    Pydantic schema types, network constraints, and cryptographic integrity.
    """

    VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
    VALID_ACTIONS = {"allow", "deny", "alert", "login", "logout"}

    def validate(self, event_dict: Dict[str, Any], verify_hash: bool = True) -> Tuple[bool, Optional[UniversalEvent], Optional[str]]:
        """
        Validates event dictionary.
        Returns: (is_valid, UniversalEvent_instance_if_valid, error_message_if_invalid)
        """
        # 1. Structural and type validation via Pydantic
        try:
            event_obj = UniversalEvent.model_validate(event_dict)
        except PydanticValidationError as e:
            errors_str = "; ".join([f"{'.'.join(str(loc) for loc in err['loc'])}: {err['msg']}" for err in e.errors()])
            return False, None, f"Schema validation error: {errors_str}"
        except Exception as e:
            return False, None, f"Unexpected validation exception: {str(e)}"

        # 2. Event ID format validation
        if not event_obj.event_id or not isinstance(event_obj.event_id, str):
            return False, None, "Missing or invalid event_id"

        # 3. Cryptographic hash verification
        if verify_hash:
            raw_data = event_obj.raw.data
            expected_hash = event_obj.metadata.raw_event_hash
            if not verify_sha256(raw_data, expected_hash):
                return False, None, f"SHA-256 hash mismatch! Data may be corrupted or tampered."

        # 4. Logical network constraints
        if event_obj.source.ip:
            try:
                ipaddress.ip_address(event_obj.source.ip)
            except ValueError:
                return False, None, f"Invalid source IP address: {event_obj.source.ip}"

        if event_obj.destination.ip:
            try:
                ipaddress.ip_address(event_obj.destination.ip)
            except ValueError:
                return False, None, f"Invalid destination IP address: {event_obj.destination.ip}"

        if event_obj.source.port is not None:
            if not (1 <= event_obj.source.port <= 65535):
                return False, None, f"Source port out of range (1-65535): {event_obj.source.port}"

        if event_obj.destination.port is not None:
            if not (1 <= event_obj.destination.port <= 65535):
                return False, None, f"Destination port out of range (1-65535): {event_obj.destination.port}"

        return True, event_obj, None


default_validator = Validator()
