from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import datetime
import os


class Certificate:
    def __init__(self, path, cert_url, self_signed_days=365):
        self.path = path
        self.cert_url = cert_url
        self.self_signed_days = self_signed_days

    @staticmethod
    def create_dir_if_not_exist(path):
        if not os.path.exists(path):
            os.makedirs(path)
            # print(f'Path: {path} created')
            return path
        elif os.path.exists(path):
            # print(f'Existed path: {path}, would not create')
            return path

    # Generate our key
    def generate_key(self, key_path='key.pem'):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Write our key to disk for safe keeping
        with open(f"{Certificate.create_dir_if_not_exist(self.path)}/{key_path}", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b"PASSCODE"),
            ))
        return key

    # Generate a CSR
    def generate_csr(self, key, csr_path='csr.pem'):
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Provide various details about who we are.
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Indiana"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Indianapolis"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Eli Lilly and Company"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"China IT"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.cert_url),
        ])).add_extension(
            x509.SubjectAlternativeName([
                # Describe what sites we want this certificate for.
                x509.DNSName(self.cert_url),
                # x509.DNSName(u"www.mysite.com"),
                # x509.DNSName(u"subdomain.mysite.com"),
            ]),
            critical=False,
            # Sign the CSR with our private key.
        ).sign(key, hashes.SHA256())
        # Write our CSR out to disk.
        with open(f"{Certificate.create_dir_if_not_exist(self.path)}/{csr_path}", "wb") as f:
            f.write(csr.public_bytes(serialization.Encoding.PEM))

    def generate_self_signed_cert(self, key, cert_path='certificate.pem'):
        # Various details about who we are. For a self-signed certificate the
        # subject and issuer are always the same.
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Indiana"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Indianapolis"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Eli Lilly and Company"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"China IT"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.cert_url),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=self.self_signed_days)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(self.cert_url)]),
            # x509.SubjectAlternativeName([x509.DNSName("www.example.com")]),
            critical=False,
            # Sign our certificate with our private key
        ).sign(key, hashes.SHA256())
        # Write our certificate out to disk.
        with open(f"{Certificate.create_dir_if_not_exist(self.path)}/{cert_path}", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))


if __name__ == "__main__":
    dir_path = 'test123.lilly.com'
    cert_url = u'test123.lilly.com'

    cert = Certificate(path=dir_path, cert_url=cert_url)
    p_key = cert.generate_key()
    cert.generate_csr(key=p_key)
    cert.generate_self_signed_cert(key=p_key)
