import os
import sys


# import datetime
#
# from cryptography import x509
# from cryptography.hazmat.primitives import serialization as crypto_serialization, hashes, serialization
# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.backends import default_backend as crypto_default_backend
# from cryptography.x509.oid import NameOID


def get_google_root_ca(resources_path, custom_ca_cert=None):
    """
    Get Google IoT Core root cert or custom CA certificate path.
    """
    if custom_ca_cert:
        return custom_ca_cert
    return os.path.join(resources_path, "roots.pem")


def get_gateway_private_key(logger, udmi_site_model_path, gateway_id, required=True):
    """
    Get private key file, for the Google IoT Core authentication
    Args:
        logger: Logger
        udmi_site_model_path: UDMI Site Model path
        gateway_id: ID of Google Iot Core gateway device
        required: Exit if private key is missing
    Returns:
        Tuple of (private_key_path, algorithm, pkcs8_key_path)
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

    logger.error(
        f"Private key not found! Please make sure that either 'rsa_private.pem' or 'ec_private.pem' file is at '{device_dir}' path")
    sys.exit(1)

# def _generate_rsa_key():
#     key = rsa.generate_private_key(
#         backend=crypto_default_backend(),
#         public_exponent=65537,
#         key_size=2048
#     )
#     return key
#
#
# def _generate_private_key(key):
#     private_key = key.private_bytes(
#         crypto_serialization.Encoding.PEM,
#         crypto_serialization.PrivateFormat.PKCS8,
#         crypto_serialization.NoEncryption())
#     return private_key
#
#
# def _generate_public_key(key):
#     public_key = key.public_key().public_bytes(
#         crypto_serialization.Encoding.PEM,
#         crypto_serialization.PublicFormat.PKCS1
#     )
#     return "public", public_key
#
#
# def _generate_certificate(key):
#     subject = issuer = x509.Name([
#         x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
#         x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Bavaria"),
#         x509.NameAttribute(NameOID.LOCALITY_NAME, u"Munich"),
#         x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MOXA Inc."),
#         x509.NameAttribute(NameOID.COMMON_NAME, u"moxa.com"),
#     ])
#     cert = x509.CertificateBuilder().subject_name(
#         subject
#     ).issuer_name(
#         issuer
#     ).public_key(
#         key.public_key()
#     ).serial_number(
#         x509.random_serial_number()
#     ).not_valid_before(
#         datetime.datetime.utcnow()
#     ).not_valid_after(
#         # Our certificate will be valid for 10 days
#         datetime.datetime.utcnow() + datetime.timedelta(days=30)
#     ).add_extension(
#         x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
#         critical=False,
#         # Sign our certificate with our private key
#     ).sign(key, hashes.SHA256())
#     return "cert", cert.public_bytes(serialization.Encoding.PEM)
#
#
# def generate_key_files(logger, algorithm="RSA_X509", regenerate=False):
#     logger.info("Generating private and public keys")
#
#     resources_path = os.environ['GOOGLE_IOT_CORE_GATEWAY_RESOURCES_PATH']
#     private_key_file_path = os.path.join(resources_path, "rsa_private.pem")
#
#     if not regenerate and os.path.exists(private_key_file_path):
#         logger.info("Keys exists, skipping")
#         if algorithm == "RSA":
#             return private_key_file_path, os.path.join(resources_path, "rsa_public.pem")
#         else:
#             return private_key_file_path, os.path.join(resources_path, "rsa_cert.pem")
#
#     key = _generate_rsa_key()
#
#     private_key = _generate_private_key(key)
#
#     if algorithm == "RSA":
#         name, content = _generate_public_key(key)
#     else:
#         name, content = _generate_certificate(key)
#
#     public_key_file_path = "{}/rsa_{}.pem".format(resources_path, name)
#
#     with open(private_key_file_path, 'wb') as content_file:
#         content_file.write(private_key)
#     with open(public_key_file_path, "wb") as content_file:
#         content_file.write(content)
#
#     return private_key_file_path, public_key_file_path
