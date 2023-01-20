"""Low-level example of how to spend a standard pay-to-pubkey-hash (P2PKH) txout"""

import hashlib

from bitcoin import SelectParams
from bitcoin.core import (
    COIN,
    CMutableTransaction,
    CMutableTxIn,
    CMutableTxOut,
    COutPoint,
    Hash160,
    b2x,
    lx,
)
from bitcoin.core.script import (
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUALVERIFY,
    OP_HASH160,
    SIGHASH_ALL,
    CScript,
    SignatureHash,
)
from bitcoin.core.scripteval import SCRIPT_VERIFY_P2SH, VerifyScript
from bitcoin.wallet import CBitcoinAddress, CBitcoinSecret

SelectParams("mainnet")

# Create the (in)famous correct brainwallet secret key.
# h = hashlib.sha256(b"correct horse battery staple").digest()
seckey = CBitcoinSecret.from_secret_bytes(
    b"\x16\xf3_\xa4\xed\x01N\xcd\x10\x9a8Lk\xabs\xc1 \xe6\x0bBK\xd0\xad\xcf\x1c\x9b\xef'\x0f\xc4r\x82"
)

print("pub", seckey.pub)

# Same as the txid:vout the createrawtransaction RPC call requires
#
# lx() takes *little-endian* hex and converts it to bytes; in Bitcoin
# transaction hashes are shown little-endian rather than the usual big-endian.
# There's also a corresponding x() convenience function that takes big-endian
# hex and converts it to bytes.
txid = lx("3de9965b3615cf32320b910e7d50a61abfa9aaab109246ca762d7e343ac737fa")
vout = 0

# Create the txin structure, which includes the outpoint. The scriptSig
# defaults to being empty.
txin = CMutableTxIn(COutPoint(txid, vout))

# We also need the scriptPubKey of the output we're spending because
# SignatureHash() replaces the transaction scriptSig's with it.
#
# Here we'll create that scriptPubKey from scratch using the pubkey that
# corresponds to the secret key we generated above.
txin_scriptPubKey = CScript(
    [
        OP_DUP,
        OP_HASH160,
        Hash160(seckey.pub),
        OP_EQUALVERIFY,
        OP_CHECKSIG,
    ]
)

# Create the txout. This time we create the scriptPubKey from a Bitcoin
# address.

txout1 = CMutableTxOut(
    0.5 * COIN,
    b"v\xa9\x14w\x87n\xfd\xb9\r%\xa17\xee\xd8\xa4E\x10|\xb1\xbf\x12w&\x88\xac",
)
txout2 = CMutableTxOut(
    4.49999775 * COIN,
    b"v\xa9\x14\x9a\x12\xd8\xdf;>ib\x9f\x87\xfb\xe2[\xd2\x03I\xfb+8\x9a\x88\xac",
)
# Create the unsigned transaction.
tx = CMutableTransaction([txin], [txout1, txout2])

# Calculate the signature hash for that transaction.
sighash = SignatureHash(txin_scriptPubKey, tx, 0, SIGHASH_ALL)
print(sighash)

# Now sign it. We have to append the type of signature we want to the end, in
# this case the usual SIGHASH_ALL.
sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])

# Set the scriptSig of our transaction input appropriately.
txin.scriptSig = CScript([sig, seckey.pub])

# Verify the signature worked. This calls EvalScript() and actually executes
# the opcodes in the scripts to see if everything worked out. If it doesn't an
# exception will be raised.
VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))

# Done! Print the transaction to standard output with the bytes-to-hex
# function.
print(b2x(tx.serialize()))
