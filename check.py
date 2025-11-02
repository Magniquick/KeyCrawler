# -*- coding: utf-8 -*-
# @Time: 2024/7/28 19:55
# @FileName: event.py
# @Software: PyCharm
# @GitHub: KimmyXYC

# Yep, completely stolen from @KimmyXYC. give them some love !

import re
import time
from datetime import datetime, timezone

import lxml.etree as ET
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding

_SUPPRESSED_ERROR_KEYWORDS = ("Unable to load PEM file", "MalformedFraming")


def _should_suppress_error(error: Exception) -> bool:
    return any(keyword in str(error) for keyword in _SUPPRESSED_ERROR_KEYWORDS)


url = "https://android.googleapis.com/attestation/status"
headers = {
    "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
    "Pragma": "no-cache",
    "Expires": "0",
}

params = {"ts": int(time.time())}

response = requests.get(url, headers=headers, params=params)
if response.status_code != 200:
    raise Exception(f"Error fetching data: {response.reason}")
status_json = response.json()


def parse_number_of_certificates(xml_string):
    root = ET.fromstring(xml_string)

    number_of_certificates = root.find(".//NumberOfCertificates")

    if number_of_certificates is not None and number_of_certificates.text is not None:
        count = int(number_of_certificates.text.strip())
        return count
    else:
        raise Exception("No NumberOfCertificates found.")


def parse_certificates(xml_string, pem_number):
    root = ET.fromstring(xml_string)

    pem_certificates = root.findall('.//Certificate[@format="pem"]')

    if pem_certificates is not None:
        pem_contents = [
            cert.text.strip() if cert.text is not None else ""
            for cert in pem_certificates[:pem_number]
        ]
        return pem_contents
    else:
        raise Exception("No Certificate found.")


def parse_private_key(xml_string):
    root = ET.fromstring(xml_string)

    private_key = root.find(".//PrivateKey")
    if private_key is not None and private_key.text is not None:
        return private_key.text.strip()
    else:
        raise Exception("No PrivateKey found.")


def load_public_key_from_file(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
    return public_key


def compare_keys(public_key1, public_key2):
    return public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ) == public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def keybox_check(certificate_text):
    try:
        pem_number = parse_number_of_certificates(certificate_text)
        pem_certificates = parse_certificates(certificate_text, pem_number)
        private_key = parse_private_key(certificate_text)
    except Exception as e:
        if not _should_suppress_error(e):
            print(f"[Keybox Check Error]: {e}")
        return False

    try:
        certificate = x509.load_pem_x509_certificate(
            pem_certificates[0].encode(), default_backend()
        )
        try:
            private_key = re.sub(re.compile(r"^\s+", re.MULTILINE), "", private_key)
            private_key = serialization.load_pem_private_key(
                private_key.encode(), password=None, backend=default_backend()
            )
            check_private_key = True
        except Exception:
            check_private_key = False
    except Exception as e:
        if not _should_suppress_error(e):
            print(f"[Keybox Check Error]: {e}")
        return False

    # Certificate Validity Verification
    serial_number = certificate.serial_number
    serial_number_string = hex(serial_number)[2:].lower()
    not_valid_before = certificate.not_valid_before_utc
    not_valid_after = certificate.not_valid_after_utc
    current_time = datetime.now(timezone.utc)
    is_valid = not_valid_before <= current_time <= not_valid_after
    if not is_valid:
        return False

    # Private Key Verification
    if check_private_key:
        private_key_public_key = private_key.public_key()
        certificate_public_key = certificate.public_key()
        if not compare_keys(private_key_public_key, certificate_public_key):
            return False
    else:
        return False

    # Keychain Authentication
    for i in range(pem_number - 1):
        son_certificate = x509.load_pem_x509_certificate(
            pem_certificates[i].encode(), default_backend()
        )
        father_certificate = x509.load_pem_x509_certificate(
            pem_certificates[i + 1].encode(), default_backend()
        )

        if son_certificate.issuer != father_certificate.subject:
            return False
        signature = son_certificate.signature
        signature_algorithm = son_certificate.signature_algorithm_oid._name
        tbs_certificate = son_certificate.tbs_certificate_bytes
        public_key = father_certificate.public_key()
        try:
            if signature_algorithm in [
                "sha256WithRSAEncryption",
                "sha1WithRSAEncryption",
                "sha384WithRSAEncryption",
                "sha512WithRSAEncryption",
            ]:
                hash_algorithm = {
                    "sha256WithRSAEncryption": hashes.SHA256(),
                    "sha1WithRSAEncryption": hashes.SHA1(),
                    "sha384WithRSAEncryption": hashes.SHA384(),
                    "sha512WithRSAEncryption": hashes.SHA512(),
                }[signature_algorithm]
                padding_algorithm = padding.PKCS1v15()
                public_key.verify(
                    signature, tbs_certificate, padding_algorithm, hash_algorithm
                )
            elif signature_algorithm in [
                "ecdsa-with-SHA256",
                "ecdsa-with-SHA1",
                "ecdsa-with-SHA384",
                "ecdsa-with-SHA512",
            ]:
                hash_algorithm = {
                    "ecdsa-with-SHA256": hashes.SHA256(),
                    "ecdsa-with-SHA1": hashes.SHA1(),
                    "ecdsa-with-SHA384": hashes.SHA384(),
                    "ecdsa-with-SHA512": hashes.SHA512(),
                }[signature_algorithm]
                padding_algorithm = ec.ECDSA(hash_algorithm)
                public_key.verify(signature, tbs_certificate, padding_algorithm)
            else:
                raise ValueError("Unsupported signature algorithms")
        except Exception:
            return False

    # Root Certificate Validation
    root_certificate = x509.load_pem_x509_certificate(
        pem_certificates[-1].encode(), default_backend()
    )
    root_public_key = root_certificate.public_key()
    google_public_key = load_public_key_from_file("pem/google.pem")
    aosp_ec_public_key = load_public_key_from_file("pem/aosp_ec.pem")
    aosp_rsa_public_key = load_public_key_from_file("pem/aosp_rsa.pem")
    knox_public_key = load_public_key_from_file("pem/knox.pem")
    if compare_keys(root_public_key, google_public_key):
        pass
    elif compare_keys(root_public_key, aosp_ec_public_key):
        return False
    elif compare_keys(root_public_key, aosp_rsa_public_key):
        return False
    elif compare_keys(root_public_key, knox_public_key):
        print("Found a knox key !?")
    else:
        return False

    # Number of Certificates in Keychain
    if pem_number >= 4:
        return False

    status = None
    for i in range(pem_number):
        certificate = x509.load_pem_x509_certificate(
            pem_certificates[i].encode(), default_backend()
        )
        serial_number = certificate.serial_number
        serial_number_string = hex(serial_number)[2:].lower()
        if status_json["entries"].get(serial_number_string, None):
            status = status_json["entries"][serial_number_string]
            break
    if status is not None:
        return False

    return True
