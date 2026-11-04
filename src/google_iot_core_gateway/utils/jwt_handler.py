import datetime

import jwt
from cryptography.hazmat.primitives import serialization

DEFAULT_JWT_EXPIRES_MINUTES = 60
MAX_JWT_EXPIRES_MINUTES = 24 * 60  # ClearBlade / Cloud IoT Core maximum token lifetime


def _load_private_key(private_key_file):
    """Load PEM or DER PKCS8 private key for PyJWT."""
    with open(private_key_file, "rb") as f:
        raw_bytes = f.read()
    if raw_bytes.lstrip().startswith(b"-----BEGIN"):
        return raw_bytes.decode("utf-8")
    return serialization.load_der_private_key(raw_bytes, password=None)


def create_jwt(logger, project_id, private_key_file, algorithm, expires_minutes=DEFAULT_JWT_EXPIRES_MINUTES):
    """
    Creates a JWT (https://jwt.io) to establish an MQTT connection.
    Args:
        logger: logger
        project_id: The cloud project ID this device belongs to
        private_key_file: A path to a file containing either an RSA256 or
             ES256 private key (PEM or PKCS8 DER).
        algorithm: The encryption algorithm to use. Either 'RS256' or 'ES256'
        expires_minutes: Token lifetime in minutes (1 .. 1440)
    Returns:
        A tuple of (jwt_string, expiration_datetime_utc).
    Raises:
        ValueError: If the private_key_file does not contain a known key.
    """
    expires_minutes = max(1, min(int(expires_minutes), MAX_JWT_EXPIRES_MINUTES))

    # The time that the token was issued at
    jwt_iat = datetime.datetime.now(datetime.timezone.utc)
    # The time the token expires.
    jwt_exp = jwt_iat + datetime.timedelta(minutes=expires_minutes)

    token = {
        "iat": jwt_iat,
        "exp": jwt_exp,
        # The audience field should always be set to the GCP project id.
        "aud": project_id,
    }

    private_key = _load_private_key(private_key_file)

    logger.debug("Creating JWT using {} from private key file {}".format(
        algorithm, private_key_file
    ))

    encoded = jwt.encode(token, private_key, algorithm=algorithm)
    if isinstance(encoded, bytes):
        encoded = encoded.decode("utf-8")
    return encoded, jwt_exp
