from cert import cert

import argparse

ap = argparse.ArgumentParser()
# ap.add_argument("-d", "--debug", required=False, default='0',
#                 help="enable debug mode")
ap.add_argument("-p", "--path", default="cert_files", required=False,
                help="path to store cert files")
ap.add_argument("-u", "--url", default="example.lilly.com", required=False,
                help="url for certificate")
ap.add_argument("-m", "--method", default="key+csr", required=False,
                help="create key+csr or key+csr+cert")
args = vars(ap.parse_args())


class Client(cert.Certificate):
    def __init__(self, path, cert_url, self_signed_days=45):
        super().__init__(path, cert_url, self_signed_days)

    def create_key_csr(self):
        p_key = self.generate_key()
        print(f"Private key: key.pem is created under: {self.path}")
        self.generate_csr(p_key)
        print(f"csr: csr.pem is created under: {self.path}, with url: {self.cert_url}")

    def create_key_csr_cert(self):
        p_key = self.generate_key()
        print(f"Encrypted Private key: ca.key is created under: {self.path}")
        print(f"Non-encrypted Private key: key.pem is created under: {self.path}")
        self.generate_csr(p_key)
        print(f"csr: csr.pem is created under: {self.path}, with url: {self.cert_url}")
        self.generate_self_signed_cert(p_key)
        print(f"Self-signed certificate: certificate.pem is created under: {self.path}, with url: {self.cert_url}")


if __name__ == "__main__":
    dir_path = args['path']
    cert_url = args['url']

    client = Client(path=dir_path, cert_url=cert_url)
    if args['method'] == 'key+csr':
        client.create_key_csr()
    elif args['method'] == 'key+csr+cert':
        client.create_key_csr_cert()
    else:
        print('Invalid method argument')
