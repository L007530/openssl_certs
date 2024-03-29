from cert.cert import Certificate

import argparse

ap = argparse.ArgumentParser()
# ap.add_argument("-d", "--debug", required=False, default='0',
#                 help="enable debug mode")
ap.add_argument("-f", "--folder", default="cert_files", required=False,
                help="path to store cert files")
ap.add_argument("-u", "--url", default="example.lilly.com", required=False,
                help="url for certificate")
ap.add_argument("-c", "--pass", required=False,
                help="ca.key passphrase")
ap.add_argument("-m", "--method", default="key+csr", required=False,
                help="create key+csr or key+csr+cert")
args = vars(ap.parse_args())


class Client(Certificate):
    def __init__(self, path, cert_url, passphrase=None, self_signed_days=45, passphrase_in_str=None):
        super().__init__(path, cert_url, passphrase, self_signed_days)
        self.passphrase_in_str = passphrase_in_str
        if self.passphrase_in_str is None:
            self.passphrase_in_str = Certificate.generate_password()
            self.passphrase = Certificate.convert_str_to_bytestr(self.passphrase_in_str)
        elif len(self.passphrase_in_str) < 8:
            self.passphrase_in_str = Certificate.generate_password()
            self.passphrase = Certificate.convert_str_to_bytestr(self.passphrase_in_str)
            print("Passphrase must > or = 8 chars, using generated passphrase")
        else:
            self.passphrase = Certificate.convert_str_to_bytestr(self.passphrase_in_str)

    def create_key_csr(self):
        # create private key
        p_key = self.generate_key()
        print(f"Encrypted Private key: ca.key is created under: {self.path}, passphrase: {self.passphrase_in_str}")
        print(f"Non-encrypted Private key: key.pem is created under: {self.path}")

        # create public key
        self.generate_csr(p_key)
        print(f"csr: csr.pem is created under: {self.path}, with url: {self.cert_url}")

        # create readme.txt
        self.generate_readme(line=f"{self.cert_url}\n")
        self.generate_readme(line=f"ca.key - Encrypted Private key, passphrase: {self.passphrase_in_str}")
        self.generate_readme(line="key.pem - Non-encrypted Private key")
        self.generate_readme(line="csr.pem - Self-signed Public key")
        print(f"Readme file is created under: {self.path}")

    def create_key_csr_cert(self):
        # create private key
        p_key = self.generate_key()
        print(f"Encrypted Private key: ca.key is created under: {self.path}")
        print(f"Non-encrypted Private key: key.pem is created under: {self.path}")

        # create public key
        self.generate_csr(p_key)
        print(f"csr: csr.pem is created under: {self.path}, with url: {self.cert_url}")

        # create self-signed certificate
        self.generate_self_signed_cert(p_key)
        print(f"Self-signed certificate: certificate.pem is created under: {self.path}, with url: {self.cert_url}")

        # create readme.txt
        self.generate_readme(line=f"SAN: {self.cert_url}\n")
        self.generate_readme(line=f"ca.key - Encrypted Private key, passphrase: {self.passphrase_in_str}")
        self.generate_readme(line="key.pem - Non-encrypted Private key")
        # self.generate_readme(line="csr.pem - Certificate Signing Request (including Self-signed Publickey)")
        self.generate_readme(line="certificate.pem - Self-signed Certificate")
        print(f"Readme file is created under: {self.path}")


if __name__ == "__main__":
    dir_path = args['folder']
    cert_url = args['url']
    passphrase = None
    if args['pass'] is not None:
        passphrase = args['pass']
    # print(passphrase)
    client = Client(path=dir_path, cert_url=cert_url, passphrase_in_str=passphrase)
    if args['method'] == 'key+csr':
        client.create_key_csr()
    elif args['method'] == 'key+csr+cert':
        client.create_key_csr_cert()
    else:
        print('Invalid method argument')
