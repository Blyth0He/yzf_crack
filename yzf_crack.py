from base64 import b64decode
from Crypto.Hash import MD5
from Crypto.Cipher import AES
import sys


def build_passphase(base64_str):
    base64d_str = b64decode(base64_str).decode()
    if '-' in base64d_str:
        params = base64d_str.split('-')
        num = int(params[0]) - int(params[1])
    else:
        num = int(base64d_str)
    key = int(num) ** 2 % 4877
    md5hash = MD5.new()
    md5hash.update(str(key).encode())
    passphase = md5hash.hexdigest()[0x8:0x18]
    return passphase

class CryptoJs:
    def __init__(self, key:bytes) -> None:
        self.aes = AES.new(key, AES.MODE_ECB)

    def _strip_padding(self, padded_bytes:bytes):
        return padded_bytes.strip(padded_bytes[-1].to_bytes(1,'little'))

    def decrypt(self, b64_cipher_text: str) -> bytes:
        plain_bytes = self.aes.decrypt(b64decode(b64_cipher_text))
        return self._strip_padding(plain_bytes)

if '__main__' == __name__:
    if len(sys.argv) !=3:
        exit('USAGE: py ' + sys.argv[0] + ' [key] [encrypted_text/path_to_file]')
    key = sys.argv[1]
    try:
        with open(sys.argv[2]) as f:
            encrypted = f.read()
    except Exception as e:
        encrypted = sys.argv[2]

    passphrase = build_passphase(key)
    cj = CryptoJs(passphrase.encode())
    print(cj.decrypt(encrypted).decode())


# https://cryptojs.gitbook.io/docs/
# https://developer.mozilla.org/en-US/docs/WebAssembly/Understanding_the_text_format
# https://blog.csdn.net/qq_33682575/article/details/104602515