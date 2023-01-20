import binascii
import struct
from dataclasses import dataclass
from hashlib import blake2b

MAX_MONEY = 21000000 * 100000000
TX_EXPIRY_HEIGHT_THRESHOLD = 500000000

OVERWINTER_VERSION_GROUP_ID = 0x03C48270
OVERWINTER_TX_VERSION = 3

SAPLING_VERSION_GROUP_ID = 0x892F2085
SAPLING_TX_VERSION = 4

OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_RETURN = 0x6A

MAX_COMPACT_SIZE = 0x2000000

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

NOT_AN_INPUT = -1  # For portability of the test vectors; replaced with None for Rust


def getHashPrevouts(tx, person=b"ZcashPrevoutHash"):

    digest = blake2b(digest_size=32, person=person)
    for x in tx.vin:
        digest.update(bytes(x.utxo.prevout))
    return digest.digest()


def getHashSequence(tx, person=b"ZcashSequencHash"):
    digest = blake2b(digest_size=32, person=person)
    for x in tx.vin:
        digest.update(struct.pack("<I", x.nSequence))
    return digest.digest()


def getHashOutputs(tx, person=b"ZcashOutputsHash"):
    digest = blake2b(digest_size=32, person=person)
    for x in tx.vout:
        digest.update(bytes(x))
    return digest.digest()


def getHashJoinSplits(tx):
    digest = blake2b(digest_size=32, person=b"ZcashJSplitsHash")
    for jsdesc in tx.vJoinSplit:
        digest.update(bytes(jsdesc))
    digest.update(tx.joinSplitPubKey)
    return digest.digest()


def getHashShieldedSpends(tx):
    digest = blake2b(digest_size=32, person=b"ZcashSSpendsHash")
    for desc in tx.vShieldedSpends:
        # We don't pass in serialized form of desc as spendAuthSig is not part of the hash
        digest.update(bytes(desc.cv))
        digest.update(bytes(desc.anchor))
        digest.update(desc.nullifier)
        digest.update(bytes(desc.rk))
        digest.update(bytes(desc.proof))
    return digest.digest()


def getHashShieldedOutputs(tx):
    digest = blake2b(digest_size=32, person=b"ZcashSOutputHash")
    for desc in tx.vShieldedOutputs:
        digest.update(bytes(desc))
    return digest.digest()


def signature_hash_sapling(scriptCode, tx, nIn, nHashType, amount, consensusBranchId):
    # this is zip243
    hashPrevouts = b"\x00" * 32
    hashSequence = b"\x00" * 32
    hashOutputs = b"\x00" * 32
    hashJoinSplits = b"\x00" * 32
    hashShieldedSpends = b"\x00" * 32
    hashShieldedOutputs = b"\x00" * 32

    # amount = 500000000
    # amount = 349999325

    # print("sig hash tx", repr(tx))

    # print("sig hash scriptcode", scriptCode)
    # print("sig hash tx", binascii.hexlify(bytes(tx)))
    # print("sig hash nin", nIn)
    # print("nhashtype", nHashType)
    # print("amount", amount)
    # print("branchId", consensusBranchId)

    if not (nHashType & SIGHASH_ANYONECANPAY):
        hashPrevouts = getHashPrevouts(tx)

    if (
        (not (nHashType & SIGHASH_ANYONECANPAY))
        and (nHashType & 0x1F) != SIGHASH_SINGLE
        and (nHashType & 0x1F) != SIGHASH_NONE
    ):
        hashSequence = getHashSequence(tx)

    if (nHashType & 0x1F) != SIGHASH_SINGLE and (nHashType & 0x1F) != SIGHASH_NONE:
        hashOutputs = getHashOutputs(tx)
    elif (nHashType & 0x1F) == SIGHASH_SINGLE and 0 <= nIn and nIn < len(tx.vout):
        digest = blake2b(digest_size=32, person=b"ZcashOutputsHash")
        digest.update(bytes(tx.vout[nIn]))
        hashOutputs = digest.digest()

    if len(tx.vJoinSplit) > 0:
        hashJoinSplits = getHashJoinSplits(tx)

    if len(tx.vShieldedSpends) > 0:
        hashShieldedSpends = getHashShieldedSpends(tx)

    if len(tx.vShieldedOutputs) > 0:
        hashShieldedOutputs = getHashShieldedOutputs(tx)

    # print("hashPrevouts", binascii.hexlify(hashPrevouts))
    # print("hashSequence", binascii.hexlify(hashSequence))
    # print("hashOutputs", binascii.hexlify(hashOutputs))
    # print("hashJoinSplits", binascii.hexlify(hashJoinSplits))
    # print("hashShieldedSpends", binascii.hexlify(hashShieldedSpends))
    # print("hashShieldedOutputs", binascii.hexlify(hashShieldedOutputs))
    # print("concensusbranch", consensusBranchId)

    digest = blake2b(
        digest_size=32,
        person=b"ZcashSigHash" + struct.pack("<I", consensusBranchId),
    )

    digest.update(struct.pack("<I", tx.version_bytes()))
    digest.update(struct.pack("<I", tx.nVersionGroupId))
    digest.update(hashPrevouts)
    digest.update(hashSequence)
    digest.update(hashOutputs)
    digest.update(hashJoinSplits)
    digest.update(hashShieldedSpends)
    digest.update(hashShieldedOutputs)
    digest.update(struct.pack("<I", tx.nLockTime))
    digest.update(struct.pack("<I", tx.nExpiryHeight))
    digest.update(struct.pack("<Q", tx.valueBalance))
    digest.update(struct.pack("<I", nHashType))

    # fix this
    # if nIn != NOT_AN_INPUT:
    digest.update(bytes(tx.vin[nIn].utxo.prevout))
    digest.update(write_compact_size(len(scriptCode)) + scriptCode)
    digest.update(struct.pack("<Q", amount))

    digest.update(struct.pack("<I", tx.vin[nIn].nSequence))

    return digest.digest()


def write_compact_size(n, allow_u64=False):
    assert allow_u64 or n <= MAX_COMPACT_SIZE
    if n < 253:
        return struct.pack("B", n)
    elif n <= 0xFFFF:
        return struct.pack("B", 253) + struct.pack("<H", n)
    elif n <= 0xFFFFFFFF:
        return struct.pack("B", 254) + struct.pack("<I", n)
    else:
        return struct.pack("B", 255) + struct.pack("<Q", n)


@dataclass
class Script:
    _script: bytes = b""

    @staticmethod
    def from_bytes(b):
        script = Script()
        script._script = b
        return script

    @staticmethod
    def encode(operations: list):
        encoded = b""
        for op in operations:
            if isinstance(op, int):
                encoded += op.to_bytes(1, "big")
            else:
                # binary_op = binascii.unhexlify(op)
                encoded += write_compact_size(len(op)) + op
        return encoded

    def raw(self):
        return self._script

    def __bytes__(self):
        return write_compact_size(len(self._script)) + self._script


class P2PKHScript(Script):
    def __init__(self, pubkey_hash: bytes):
        self._script = self.encode(
            [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
        )


class MessageScript(Script):
    def __init__(self, message: str):
        self._script = self.encode([OP_RETURN, message.encode("utf-8")])


@dataclass
class OutPoint:
    txid: bytes
    n: int

    def __bytes__(self):
        return self.txid + struct.pack("<I", self.n)


@dataclass
class UTXO:
    prevout: OutPoint
    scriptPubKey: Script


@dataclass
class TxIn:
    utxo: UTXO
    scriptSig: Script
    nSequence: int

    def __bytes__(self):
        return (
            bytes(self.utxo.prevout)
            + bytes(self.scriptSig)
            + struct.pack("<I", self.nSequence)
        )


@dataclass
class TxOut:
    nValue: int
    script: Script

    def __bytes__(self):
        return struct.pack("<Q", self.nValue) + bytes(self.script)


class LegacyTransaction(object):
    def __init__(
        self,
        version,
        vin: list[TxIn] = [],
        vout: list[TxOut] = [],
        nLockTime: int = 0,
        nExpiryHeight: int = 0,
        valuebalance: int = 0,
        shielded_spends: list = [],
        shielded_outputs: list = [],
    ):
        if version == OVERWINTER_TX_VERSION:
            self.fOverwintered = True
            self.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
            self.nVersion = OVERWINTER_TX_VERSION
        elif version == SAPLING_TX_VERSION:
            self.fOverwintered = True
            self.nVersionGroupId = SAPLING_VERSION_GROUP_ID
            self.nVersion = SAPLING_TX_VERSION
        else:
            raise Exception("Unsupported version")

        self.vin = []
        for tx in vin:
            self.vin.append(tx)

        self.vout = []
        for tx in vout:
            self.vout.append(tx)

        self.nLockTime = nLockTime
        self.nExpiryHeight = nExpiryHeight % TX_EXPIRY_HEIGHT_THRESHOLD
        if self.nVersion >= SAPLING_TX_VERSION:
            self.valueBalance = valuebalance % (MAX_MONEY + 1)

        self.vShieldedSpends = []
        self.vShieldedOutputs = []
        if self.nVersion >= SAPLING_TX_VERSION:
            for spend in shielded_spends:
                self.vShieldedSpends.append(spend)
            for output in shielded_outputs:
                self.vShieldedOutputs.append(output)

        self.vJoinSplit = []

    def version_bytes(self):
        return self.nVersion | (1 << 31 if self.fOverwintered else 0)

    def __bytes__(self):
        ret = b""
        ret += struct.pack("<I", self.version_bytes())
        if self.fOverwintered:
            ret += struct.pack("<I", self.nVersionGroupId)

        isOverwinterV3 = (
            self.fOverwintered
            and self.nVersionGroupId == OVERWINTER_VERSION_GROUP_ID
            and self.nVersion == OVERWINTER_TX_VERSION
        )

        isSaplingV4 = (
            self.fOverwintered
            and self.nVersionGroupId == SAPLING_VERSION_GROUP_ID
            and self.nVersion == SAPLING_TX_VERSION
        )

        ret += write_compact_size(len(self.vin))
        for x in self.vin:
            ret += bytes(x)

        ret += write_compact_size(len(self.vout))
        for x in self.vout:
            ret += bytes(x)

        ret += struct.pack("<I", self.nLockTime)
        if isOverwinterV3 or isSaplingV4:
            ret += struct.pack("<I", self.nExpiryHeight)

        if isSaplingV4:
            ret += struct.pack("<Q", self.valueBalance)
            ret += write_compact_size(len(self.vShieldedSpends))
            for desc in self.vShieldedSpends:
                ret += bytes(desc)
            ret += write_compact_size(len(self.vShieldedOutputs))
            for desc in self.vShieldedOutputs:
                ret += bytes(desc)

        if self.nVersion >= 2:
            ret += write_compact_size(len(self.vJoinSplit))
            for jsdesc in self.vJoinSplit:
                ret += bytes(jsdesc)
            if len(self.vJoinSplit) > 0:
                ret += self.joinSplitPubKey
                ret += self.joinSplitSig

        if isSaplingV4 and not (
            len(self.vShieldedSpends) == 0 and len(self.vShieldedOutputs) == 0
        ):
            ret += self.bindingSig

        return ret

    def __repr__(self):
        resp = ""
        for k, v in self.__dict__.items():
            resp += f"{k}: {v}\n"
        return resp
