import struct
from dataclasses import dataclass
from hashlib import blake2b
from io import BytesIO
from typing import BinaryIO
from fluxwallet.encoding import read_varbyteint

MAX_MONEY = 21000000 * 100000000
TX_EXPIRY_HEIGHT_THRESHOLD = 500000000

OVERWINTER_VERSION_GROUP_ID = 0x03C4827
OVERWINTER_TX_VERSION = 3

SAPLING_VERSION_GROUP_ID = 0x892F2085
SAPLING_TX_VERSION = 4

OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_RETURN = 0x6A

MAX_COMPACT_SIZE = 0x2000000

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80





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

    def __bool__(self):
        return bool(self._script)

    def __bytes__(self):
        return write_compact_size(len(self._script)) + self._script

    @staticmethod
    def encode(operations: list):
        encoded = b""
        for op in operations:
            if isinstance(op, int):
                encoded += op.to_bytes(1, "big")
            else:
                encoded += write_compact_size(len(op)) + op
        return encoded

    @classmethod
    def from_bytes(cls, b: bytes):
        try:
            b: BinaryIO = BytesIO(b)
        except TypeError:
            script = cls()
            script._script = b
            return script

        op = b.read(1)
        op = int.from_bytes(op, "little")
        match op:
            case x if x == OP_RETURN:
                size = read_varbyteint(b)
                data = b.read(size)
                msg = MessageScript(data.decode())
            case x if x == OP_HASH160:
                # p2sh
                size = read_varbyteint(b)
                script_hash = b.read(size)
                op_equal = int.from_bytes(b.read(1), "little")
                assert op_equal == OP_EQUAL
                msg = P2SHScript(script_hash)
            case x if x == OP_DUP:
                # p2pkh
                hash160 = int.from_bytes(b.read(1), "little")
                assert hash160 == OP_HASH160
                size = read_varbyteint(b)
                pubkey_hash = b.read(size)
                op_equalverify = int.from_bytes(b.read(1), "little")
                assert op_equalverify == OP_EQUALVERIFY
                op_checksig = int.from_bytes(b.read(1), "little")
                assert op_checksig == OP_CHECKSIG
                msg = P2PKHScript(pubkey_hash)
            case _:
                # raise ValueError("Unknown script")
                script = cls()
                script._script = b.getvalue()
                msg = script

        return msg

    def raw(self):
        return self._script


class P2PKHScript(Script):
    def __init__(self, pubkey_hash: bytes):
        self._script = self.encode(
            [OP_DUP, OP_HASH160, pubkey_hash, OP_EQUALVERIFY, OP_CHECKSIG]
        )


class P2SHScript(Script):
    def __init__(self, script_hash: bytes):
        self._script = self.encode([OP_HASH160, script_hash, OP_EQUAL])


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
class TxIn:
    prevout: OutPoint
    scriptSig: Script
    nSequence: int

    def __bytes__(self):
        return (
            bytes(self.prevout)
            + bytes(self.scriptSig)
            + struct.pack("<I", self.nSequence)
        )


@dataclass
class TxOut:
    nValue: int
    script: Script

    def __bytes__(self):
        return struct.pack("<Q", self.nValue) + bytes(self.script)


class SaplingTx(object):
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


    def version_bytes(self):
        return self.nVersion | (1 << 31 if self.fOverwintered else 0)

    def getHashPrevouts(self, person=b"ZcashPrevoutHash"):
        digest = blake2b(digest_size=32, person=person)

        for x in self.vin:
            digest.update(bytes(x.prevout))
        return digest.digest()


    def getHashSequence(self, person=b"ZcashSequencHash"):
        digest = blake2b(digest_size=32, person=person)

        for x in self.vin:
            digest.update(struct.pack("<I", x.nSequence))
        return digest.digest()


    def getHashOutputs(self, person=b"ZcashOutputsHash"):
        digest = blake2b(digest_size=32, person=person)
        for x in self.vout:
            digest.update(bytes(x))
        return digest.digest()


    def getHashJoinSplits(self):
        digest = blake2b(digest_size=32, person=b"ZcashJSplitsHash")
        for jsdesc in self.vJoinSplit:
            digest.update(bytes(jsdesc))
        digest.update(self.joinSplitPubKey)
        return digest.digest()


    def getHashShieldedSpends(self):
        digest = blake2b(digest_size=32, person=b"ZcashSSpendsHash")
        for desc in self.vShieldedSpends:
            # We don't pass in serialized form of desc as spendAuthSig is not part of the hash
            digest.update(bytes(desc.cv))
            digest.update(bytes(desc.anchor))
            digest.update(desc.nullifier)
            digest.update(bytes(desc.rk))
            digest.update(bytes(desc.proof))
        return digest.digest()


    def getHashShieldedOutputs(self):
        digest = blake2b(digest_size=32, person=b"ZcashSOutputHash")
        for desc in self.vShieldedOutputs:
            digest.update(bytes(desc))
        return digest.digest()


    def signature_hash(self, script_code: bytes, value: int, input_n: int, nIn: int, hash_type: str=SIGHASH_ALL) -> bytes:
        consensusBranchId = 0x76B809BB  # Sapling
        if input_n == None:
            return b""


        # this is zip243
        hashPrevouts = b"\x00" * 32
        hashSequence = b"\x00" * 32
        hashOutputs = b"\x00" * 32
        hashJoinSplits = b"\x00" * 32
        hashShieldedSpends = b"\x00" * 32
        hashShieldedOutputs = b"\x00" * 32

        if not (hash_type & SIGHASH_ANYONECANPAY):
            hashPrevouts = self.getHashPrevouts()

        if (
            (not (hash_type & SIGHASH_ANYONECANPAY))
            and (hash_type & 0x1F) != SIGHASH_SINGLE
            and (hash_type & 0x1F) != SIGHASH_NONE
        ):
            hashSequence = self.getHashSequence()

        if (hash_type & 0x1F) != SIGHASH_SINGLE and (hash_type & 0x1F) != SIGHASH_NONE:
            hashOutputs = self.getHashOutputs()
        elif (hash_type & 0x1F) == SIGHASH_SINGLE and 0 <= nIn and nIn < len(self.vout):
            digest = blake2b(digest_size=32, person=b"ZcashOutputsHash")
            digest.update(bytes(self.vout[nIn]))
            hashOutputs = digest.digest()

        if len(self.vJoinSplit) > 0:
            hashJoinSplits = self.getHashJoinSplits()

        if len(self.vShieldedSpends) > 0:
            hashShieldedSpends = self.getHashShieldedSpends()

        if len(self.vShieldedOutputs) > 0:
            hashShieldedOutputs = self.getHashShieldedOutputs()

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

        digest.update(struct.pack("<I", self.version_bytes()))
        digest.update(struct.pack("<I", self.nVersionGroupId))
        digest.update(hashPrevouts)
        digest.update(hashSequence)
        digest.update(hashOutputs)
        digest.update(hashJoinSplits)
        digest.update(hashShieldedSpends)
        digest.update(hashShieldedOutputs)
        digest.update(struct.pack("<I", self.nLockTime))
        digest.update(struct.pack("<I", self.nExpiryHeight))
        digest.update(struct.pack("<Q", self.valueBalance))
        digest.update(struct.pack("<I", hash_type))

        digest.update(bytes(self.vin[input_n].prevout))
        digest.update(write_compact_size(len(script_code)) + script_code)
        digest.update(struct.pack("<Q", value))

        digest.update(struct.pack("<I", self.vin[input_n].nSequence))

        return digest.digest()