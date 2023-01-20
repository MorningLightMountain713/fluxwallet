import binascii
import hashlib

import ecdsa
from ecdsa.util import sigencode_der

x = 10380886617866757582534387140308981496341948758361153323446672954612880011906
print(x.to_bytes(32, "big"))

sk = ecdsa.SigningKey.from_string(
    b"\x16\xf3_\xa4\xed\x01N\xcd\x10\x9a8Lk\xabs\xc1 \xe6\x0bBK\xd0\xad\xcf\x1c\x9b\xef'\x0f\xc4r\x82",
    curve=ecdsa.SECP256k1,
)

sig = sk.sign_deterministic(
    binascii.unhexlify(
        b"eb274778b49a83bd066bc4bc2af7c0f7e8b4d94e75ff80ef24692c5f74f263d2"
    ),
    sigencode=sigencode_der,
    hashfunc=hashlib.sha256,
)

# sig += 0x01.to_bytes(1, "big")

print(binascii.hexlify(sig))

################################################################################################


# from bitcoin.wallet import CBitcoinSecret
# import binascii

# seckey = CBitcoinSecret.from_secret_bytes(
#     b"\x16\xf3_\xa4\xed\x01N\xcd\x10\x9a8Lk\xabs\xc1 \xe6\x0bBK\xd0\xad\xcf\x1c\x9b\xef'\x0f\xc4r\x82"
# )

# sighash = b"eb274778b49a83bd066bc4bc2af7c0f7e8b4d94e75ff80ef24692c5f74f263d2"

# sig = seckey.sign(binascii.unhexlify(sighash))

# print(binascii.hexlify(sig))

################################################################################################
