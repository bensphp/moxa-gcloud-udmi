# This software is licensed under GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007

"""Helpers for resolving the upstream MQTT bridge CA bundle and gateway private key."""

import os

from google_iot_core_gateway.errors import GatewayConfigError


def get_google_root_ca(resources_path, custom_ca_cert=None):
    """
    Get the CA bundle used to verify the MQTT bridge.
    Returns:
        Tuple of (ca_cert_path, is_explicit): `is_explicit` is True for a configured/custom CA
        (which must exist) and False for the bundled default `resources/roots.pem`.
    """
    if custom_ca_cert:
        return custom_ca_cert, True
    return os.path.join(resources_path, "roots.pem"), False


def get_gateway_private_key(logger, udmi_site_model_path, gateway_id, required=True):
    """
    Get private key file, for the Google IoT Core authentication
    Args:
        logger: Logger
        udmi_site_model_path: UDMI Site Model path
        gateway_id: ID of Google Iot Core gateway device
        required: Raise GatewayConfigError if the private key is missing
    Returns:
        Tuple of (private_key_path, algorithm); private_key_path is None if not required and missing
    """
    device_dir = os.path.join(udmi_site_model_path, "devices", gateway_id)

    candidates = [
        ("rsa_private.pem", "RS256"),
        ("ec_private.pem", "ES256"),
    ]
    for filename, algorithm in candidates:
        private_key_file_path = os.path.join(device_dir, filename)
        if os.path.exists(private_key_file_path):
            return private_key_file_path, algorithm

    # Fallback: check PKCS8 PEM or convert/detect if only .pkcs8 exists in UDMI site model
    pkcs8_candidates = [
        ("rsa_private.pkcs8", "RS256"),
        ("ec_private.pkcs8", "ES256"),
    ]
    for filename, algorithm in pkcs8_candidates:
        pkcs8_path = os.path.join(device_dir, filename)
        if os.path.exists(pkcs8_path):
            return pkcs8_path, algorithm

    if not required:
        logger.warning(f"No private key found at '{device_dir}'; continuing without JWT key.")
        return None, "RS256"

    raise GatewayConfigError(
        f"Private key not found: expected 'rsa_private.pem' or 'ec_private.pem' in '{device_dir}'"
    )
