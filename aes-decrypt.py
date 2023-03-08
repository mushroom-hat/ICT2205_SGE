import hashlib
import io
from cryptography.fernet import Fernet

import pyzipper
import os, binascii
import pbkdf2
from zipfile import ZipFile, BadZipFile

salt = binascii.unhexlify('244ABC8A36966642')

with open("rockyou.txt", 'r') as f:
        for l in f:
            try:

                l = l.strip()
                key = hashlib.pbkdf2_hmac("sha1", l.encode("utf-8"), salt, 1000, 16)
                fernet = Fernet(key)

                # opening the encrypted file
                with open('unknown.zip', 'rb') as enc_file:
                    encrypted = enc_file.read()

                # decrypting the file
                decrypted = fernet.decrypt(encrypted)

                # opening the file in write mode and
                # writing the decrypted data
                with open('unknown.zip', 'wb') as dec_file:
                    dec_file.write(decrypted)
                print(l)
                break
            except Exception:
                pass
