from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import datetime
import os
import random
import string


class Certificate:
    def __init__(self, path, cert_url, passphrase, self_signed_days=365):
        self.path = path
        self.cert_url = cert_url
        self.passphrase = passphrase
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

    @staticmethod
    def generate_password(length=8, exclude_chars='#-'):
        # 确保密码长度至少为 4，以满足包含大写字母、小写字母、数字和特殊字符的要求
        if length < 4:
            print("Password length must be at least 4")
            return None

        # 定义字符集，移除排除的字符
        uppercase_letters = string.ascii_uppercase
        lowercase_letters = string.ascii_lowercase
        digits = string.digits
        special_characters = string.punctuation.translate({ord(c): None for c in exclude_chars})

        # 随机选择一个大写字母作为密码的第一个字符
        password = [random.choice(uppercase_letters)]

        # 随机选择一个数字、一个小写字母和一个特殊字符
        password.append(random.choice(digits))
        password.append(random.choice(lowercase_letters))
        password.append(random.choice(special_characters))

        # 填充剩下的位置，以随机的字符
        all_characters = uppercase_letters + lowercase_letters + digits + special_characters
        for i in range(length - 4):
            password.append(random.choice(all_characters))

        # 打乱密码中的字符顺序
        random.shuffle(password[1:])

        # 将字符列表转换为字符串
        return ''.join(password)

    @staticmethod
    def convert_str_to_bytestr(str_inputed):
        return bytes(str_inputed, 'utf-8')

    def generate_readme(self, file_name='readme', line=''):
        with open(f"{Certificate.create_dir_if_not_exist(self.path)}/{file_name}_{self.cert_url}.txt", "a") as rdm:
            rdm.write(f"{line}\n")

    # Generate encrypted private key as ca.key
    def generate_key(self, key_path='ca.key'):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Write our key to disk for safe keeping
        with open(f"{Certificate.create_dir_if_not_exist(self.path)}/{key_path}", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(self.passphrase),
            ))
        self.convert_key_to_nonencrypted()
        return key

    # Save none encrypted private key as key.pem
    def convert_key_to_nonencrypted(self, key_path='ca.key', nonencrypted_key_path='key.pem'):
        with open(f"{Certificate.create_dir_if_not_exist(self.path)}/{key_path}", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=self.passphrase,
            )

        with open(f"{Certificate.create_dir_if_not_exist(self.path)}/{nonencrypted_key_path}", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

    # Generate a CSR as csr.pem
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

    # Generate self signed cert as certificate.pem
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

    # cert = Certificate(path=dir_path, cert_url=cert_url)
    # p_key = cert.generate_key()
    # cert.generate_csr(key=p_key)
    # cert.generate_self_signed_cert(key=p_key)
    passphrase1=Certificate.generate_password()
    print(passphrase1)
    passphrase2 = Certificate.generate_password(12)
    print(passphrase2)
    passphrase3 = Certificate.generate_password(10, '%&')
    print(passphrase3)

    pass
