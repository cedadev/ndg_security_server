#!/usr/bin/env python
from M2Crypto import X509, RSA

text = 'Hello world'
x509Cert = X509.load_cert('./test.crt')
rsaPubKey = x509Cert.get_pubkey().get_rsa()
encrypted = rsaPubKey.public_encrypt(text, RSA.pkcs1_padding)

priKey = RSA.load_key('./test.key')
decrypted = priKey.private_decrypt(encrypted, RSA.pkcs1_padding)
print decrypted

