# openssl certificate generate client

```bash
cert_client.exe
options:
  -h, --help, show this help message and exit
  -f, --folder, path to store cert files, default=cert_files
  -u, --url, url for certificate, default=example.lilly.com
  -c, --pass, ca.key passphrase, default=[random 8 chars with letter, number, specical char], specified passphrase must >=8 char
  -m, --method, create key+csr or key+csr+cert, default=key+csr
```

example:
```bash
python cert_client.py --folder icontent.clientapp.lilly.com --url icontent.clientapp.lilly.com --pass PASSPHRASE123
```

```bash
cert_client.exe --folder icontent.clientapp.lilly.com --url icontent.clientapp.lilly.com
```
