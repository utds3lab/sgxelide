import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

f = open('enclave.secret.meta','rb')
j = json.load(f)
f.close()

print j

backend = default_backend()
cipher = Cipher(algorithms.AES(base64.b64decode(j['key'])), modes.GCM(base64.b64decode(j['iv']), base64.b64decode(j['tag'])), backend=backend)
decryptor = cipher.decryptor()

f = open('enclave.secret.dat','rb')
ct = f.read()
plaintext = decryptor.update(ct) + decryptor.finalize()

print plaintext[:4096].encode('hex')
