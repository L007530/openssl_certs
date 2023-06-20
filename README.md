# cert_openssl

```python
python cert_client.py --folder output_folder --url example.lilly.com --method key+csr --passphrase PASSPHRASE
```


```bash
-f --folder path to output certificate file, default="cert_files"
-u --url certificate common name and SAN, default="example.lilly.com"
-m --method key+csr or key+csr+cert, default="key+csr"
--passphras passphras for ca.key, default="PASSPHRASE"

