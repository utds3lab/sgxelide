import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

f = open('enclave.secret.meta','rb')
#j = json.load(f)
contents = f.read()
contents = contents.split('\n')#if a newline was generated this will break
#print contents[3]
key = contents[3][:16]
iv = contents[3][16:16+12]
tag = contents[3][16+12:16+12+16]
f.close()

print key.encode('hex')
print iv.encode('hex')
print tag.encode('hex')

backend = default_backend()
#cipher = Cipher(algorithms.AES(base64.b64decode(j['key'])), modes.GCM(base64.b64decode(j['iv']), base64.b64decode(j['tag'])), backend=backend)
cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=backend)
decryptor = cipher.decryptor()

f = open('enclave.secret.dat','rb')
ct = f.read()
plaintext = decryptor.update(ct) + decryptor.finalize()

print plaintext[:4096].encode('hex')
