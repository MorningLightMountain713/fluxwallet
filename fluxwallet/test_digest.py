import binascii
from hashlib import blake2b

h = blake2b(person=b"ZcashOutputsHash", digest_size=32)
h.update(
    binascii.unhexlify(b"e7719811893e0000095200ac6551ac636565b2835a0805750200025151")
)
print(h.hexdigest())
