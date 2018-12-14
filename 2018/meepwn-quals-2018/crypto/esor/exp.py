__author__ = "polaris"

from Crypto.Cipher import AES

encrypt_key = '\xff' * 32
hmac_secret = ''
blocksize = 16
hmac_size = 20

data  = "29181366df90e89ad5860e2f8e8370658d963ba0f5ebc45bbe31069b3c5fc944b1d7852fdc73683cc029e8a749a5a6e7cfc3bce037d5e77f9cb23c8629628926ed3aef3587b73d00d3923b0ed4a183357eef2744ed282e62b85ce2d36a0b6142"
data = data.decode('hex')

iv = data[:blocksize]
_aes = AES.new(encrypt_key, AES.MODE_CBC, iv)
data = _aes.decrypt(data[blocksize:])
print data