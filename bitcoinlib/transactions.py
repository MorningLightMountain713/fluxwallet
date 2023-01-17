# -*- coding: utf-8 -*-
#
#    BitcoinLib - Python Cryptocurrency Library
#    TRANSACTION class to create, verify and sign Transactions
#    © 2017 - 2022 - 1200 Web Development <http://1200wd.com/>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from dataclasses import dataclass
import struct


from datetime import datetime
import json
import pickle
import random
from io import BytesIO
from bitcoinlib.encoding import *
from bitcoinlib.config.opcodes import *
from bitcoinlib.keys import (
    HDKey,
    Key,
    deserialize_address,
    Address,
    sign,
    verify,
    Signature,
)
from bitcoinlib.networks import Network
from bitcoinlib.values import Value, value_to_satoshi
from bitcoinlib.scripts import Script
import binascii

_logger = logging.getLogger(__name__)

from bitcoinlib.transaction_new import (
    LegacyTransaction,
    TxIn,
    TxOut,
    OutPoint,
    P2PKHScript,
    Script as NewScript,
    signature_hash_sapling,
)


class TransactionError(Exception):
    """
    Handle Transaction class Exceptions
    """

    def __init__(self, msg=""):
        self.msg = msg
        _logger.error(msg)

    def __str__(self):
        return self.msg


def get_unlocking_script_type(
    locking_script_type, witness_type="legacy", multisig=False
):
    """
    Specify locking script type and get corresponding script type for unlocking script

    >>> get_unlocking_script_type('p2wsh')
    'p2sh_multisig'

    :param locking_script_type: Locking script type. I.e.: p2pkh, p2sh, p2wpkh, p2wsh
    :type locking_script_type: str
    :param witness_type: Type of witness: legacy or segwit. Default is legacy
    :type witness_type: str
    :param multisig: Is multisig script or not? Default is False
    :type multisig: bool

    :return str: Unlocking script type such as sig_pubkey or p2sh_multisig
    """

    if locking_script_type in ["p2pkh", "p2wpkh"]:
        return "sig_pubkey"
    elif locking_script_type == "p2wsh" or (witness_type == "legacy" and multisig):
        return "p2sh_multisig"
    elif locking_script_type == "p2sh":
        if not multisig:
            return "sig_pubkey"
        else:
            return "p2sh_multisig"
    elif locking_script_type == "p2pk":
        return "signature"
    else:
        raise TransactionError("Unknown locking script type %s" % locking_script_type)


def transaction_update_spents(txs, address):
    """
    Update spent information for list of transactions for a specific address. This method assumes the list of
    transaction complete and up-to-date.

    This method loops through all the transaction and update all transaction outputs for given address, checks
    if the output is spent and add the spending transaction ID and index number to the outputs.

    The same list of transactions with updates outputs will be returned

    :param txs: Complete list of transactions for given address
    :type txs: list of Transaction
    :param address: Address string
    :type address: str

    :return list of Transaction:
    """
    spend_list = {}
    for t in txs:
        for inp in t.inputs:
            if inp.address == address:
                spend_list.update({(inp.prev_txid.hex(), inp.output_n_int): t})
    address_inputs = list(spend_list.keys())
    for t in txs:
        for to in t.outputs:
            if to.address != address:
                continue
            spent = True if (t.txid, to.output_n) in address_inputs else False
            txs[txs.index(t)].outputs[to.output_n].spent = spent
            if spent:
                spending_tx = spend_list[(t.txid, to.output_n)]
                spending_index_n = [
                    inp
                    for inp in txs[txs.index(spending_tx)].inputs
                    if inp.prev_txid.hex() == t.txid and inp.output_n_int == to.output_n
                ][0].index_n
                txs[txs.index(t)].outputs[to.output_n].spending_txid = spending_tx.txid
                txs[txs.index(t)].outputs[
                    to.output_n
                ].spending_index_n = spending_index_n
    return txs


class Input(object):
    """
    Transaction Input class, used by Transaction class

    An Input contains a reference to an UTXO or Unspent Transaction Output (prev_txid + output_n).
    To spend the UTXO an unlocking script can be included to prove ownership.

    Inputs are verified by the Transaction class.
    """

    def __init__(
        self,
        prev_txid,
        output_n,
        keys=None,
        signatures=[],
        public_hash=b"",
        unlocking_script="",
        unlocking_script_unsigned="",
        script=None,
        script_type="sig_pubkey",
        address="",
        sequence=0xFFFFFFFF,
        compressed=True,
        sigs_required=None,
        sort=False,
        index_n=0,
        value=0,
        double_spend=False,
        locktime_cltv=None,
        locktime_csv=None,
        key_path="",
        witness_type="legacy",
        witnesses=None,
        encoding="base58",
        strict=True,
        network=DEFAULT_NETWORK,
        utxo_script=b"",
    ):
        """
        Create a new transaction input

        :param prev_txid: Transaction hash of the UTXO (previous output) which will be spent.
        :type prev_txid: bytes, str
        :param output_n: Output number in previous transaction.
        :type output_n: bytes, int
        :param keys: A list of Key objects or public / private key string in various formats. If no list is provided but a bytes or string variable, a list with one item will be created. Optional
        :type keys: list (bytes, str, Key)
        :param signatures: Specify optional signatures
        :type signatures: list (bytes, str, Signature)
        :param public_hash: Public key hash or script hash. Specify if key is not available
        :type public_hash: bytes
        :param unlocking_script: Unlocking script (scriptSig) to prove ownership. Optional
        :type unlocking_script: bytes, hexstring
        :param unlocking_script_unsigned: Unlocking script for signing transaction
        :type unlocking_script_unsigned: bytes, hexstring
        :param script_type: Type of unlocking script used, i.e. p2pkh or p2sh_multisig. Default is p2pkh
        :type script_type: str
        :param address: Address string or object for input
        :type address: str, Address
        :param sequence: Sequence part of input, you normally do not have to touch this
        :type sequence: bytes, int
        :param compressed: Use compressed or uncompressed public keys. Default is compressed
        :type compressed: bool
        :param sigs_required: Number of signatures required for a p2sh_multisig unlocking script
        :type sigs_required: int
        :param sort: Sort public keys according to BIP0045 standard. Default is False to avoid unexpected change of key order.
        :type sort: boolean
        :param index_n: Index of input in transaction. Used by Transaction class.
        :type index_n: int
        :param value: Value of input in the smallest denominator integers (Satoshi's) or as Value object or string
        :type value: int, Value, str
        :param double_spend: Is this input also spend in another transaction
        :type double_spend: bool
        :param locktime_cltv: Check Lock Time Verify value. Script level absolute time lock for this input
        :type locktime_cltv: int
        :param locktime_csv: Check Sequence Verify value
        :type locktime_csv: int
        :param key_path: Key path of input key as BIP32 string or list
        :type key_path: str, list
        :param witness_type: Specify witness/signature position: 'segwit' or 'legacy'. Determine from script, address or encoding if not specified.
        :type witness_type: str
        :param witnesses: List of witnesses for inputs, used for segwit transactions for instance. Argument can be list of bytes or string or a single bytes string with concatenated witnesses as found in a raw transaction.
        :type witnesses: list of bytes, list of str, bytes
        :param encoding: Address encoding used. For example bech32/base32 or base58. Leave empty for default
        :type encoding: str
        :param strict: Raise exception when input is malformed, incomplete or not understood
        :type strict: bool
        :param network: Network, leave empty for default
        :type network: str, Network
        """

        print("In input __init__")
        print("sequence", sequence)
        print("prevtxid", prev_txid)
        self.outpoint = OutPoint(prev_txid[::-1], output_n)
        print("outpoint txid", binascii.hexlify(self.outpoint.txid))
        self.txin = TxIn(self.outpoint, NewScript(), sequence, utxo_script)
        # self.txin = TxIn(self.outpoint, NewScript(), sequence)
        print("utxo script", binascii.hexlify(utxo_script))

        self.script = None
        self.hash_type = SIGHASH_ALL

        self.compressed = compressed
        self.index_n = index_n
        self.value = value_to_satoshi(value, network=network)
        self.public_hash = public_hash
        self.sort = sort
        self.redeemscript = b""
        self.script_type = script_type
        self.double_spend = double_spend
        self.locktime_cltv = locktime_cltv
        self.locktime_csv = locktime_csv
        self.witness_type = witness_type
        self.encoding = encoding
        self.valid = None
        self.key_path = key_path
        self.script_code = b""
        self.script = script
        self.sigs_required = sigs_required if sigs_required else 1
        self.witnesses = witnesses
        self.keys = []
        self.signatures = signatures
        self.compressed = compressed
        self.keys = keys
        self.strict = strict

        print("VALUE", value)
        print("check for sigs", signatures)

        if isinstance(output_n, int):
            self.output_n_int = output_n
            self.output_n = output_n.to_bytes(4, "big")
        else:
            self.output_n_int = int.from_bytes(output_n, "big")
            self.output_n = output_n

        self.unlocking_script = to_bytes(unlocking_script)
        self.unlocking_script_unsigned = to_bytes(unlocking_script_unsigned)

        print("unlocking script", unlocking_script)
        print("unlocking script unsigned", unlocking_script_unsigned)

        if isinstance(sequence, numbers.Number):
            self.sequence = sequence
        else:
            self.sequence = int.from_bytes(sequence, "little")

        self.network = network

        if not isinstance(network, Network):
            self.network = Network(network)

        if isinstance(address, Address):
            print("Address is of type address")
            self.address = address.address
            self.encoding = address.encoding
            self.network = address.network
        else:
            self.address = address

        print("address type: ", type(address))
        print(address)

        if self.outpoint.txid == b"\0" * 32:
            self.script_type = "coinbase"

        if self.sort:
            self.keys.sort(key=lambda k: k.public_byte)

        print("signatures in input", signatures)
        for sig in signatures:
            if not isinstance(sig, Signature):
                try:
                    sig = Signature.parse(sig)
                except Exception as e:
                    _logger.error(
                        "Could not parse signature %s in Input. Error: %s"
                        % (to_hexstring(sig), e)
                    )
                    continue
            if sig.as_der_encoded() not in [
                x.as_der_encoded() for x in self.signatures
            ]:
                self.signatures.append(sig)
                if sig.hash_type:
                    self.hash_type = sig.hash_type

        self.update_scripts(hash_type=self.hash_type)

    @classmethod
    def parse(
        cls, raw, witness_type="segwit", index_n=0, strict=True, network=DEFAULT_NETWORK
    ):
        """
        Parse raw BytesIO string and return Input object

        :param raw: Input
        :type raw: BytesIO
        :param witness_type: Specify witness/signature position: 'segwit' or 'legacy'. Derived from script if not specified.
        :type witness_type: str
        :param index_n: Index number of input
        :type index_n: int
        :param strict: Raise exception when input is malformed, incomplete or not understood
        :type strict: bool
        :param network: Network, leave empty for default
        :type network: str, Network

        :return Input:
        """
        prev_hash = raw.read(32)[::-1]
        print("prev hash:", binascii.hexlify(prev_hash))
        if len(prev_hash) != 32:
            raise TransactionError(
                "Input transaction hash not found. Probably malformed raw transaction"
            )
        output_n = raw.read(4)[::-1]
        print("output_n", int(binascii.hexlify(output_n), 16))
        unlocking_script_size = read_varbyteint(raw)
        print("unlock size", unlocking_script_size)

        unlocking_script = raw.read(unlocking_script_size)
        print("unlocking", binascii.hexlify(unlocking_script))

        # TODO - handle non-standard input script b'\1\0',
        #  see tx 38cf5779d1c5ca32b79cd5052b54e824102e878f041607d3b962038f5a8cf1ed
        # if unlocking_script_size == 1 and unlocking_script == b'\0':

        inp_type = "legacy"
        if witness_type == "segwit" and not unlocking_script_size:
            inp_type = "segwit"

        sequence_number = raw.read(4)

        return Input(
            prev_txid=prev_hash,
            output_n=output_n,
            unlocking_script=unlocking_script,
            witness_type=inp_type,
            sequence=sequence_number,
            index_n=index_n,
            strict=strict,
            network=network,
        )

    def update_scripts(self, hash_type=SIGHASH_ALL):
        """
        Method to update Input scripts.

        Creates or updates unlocking script, witness script for segwit inputs, multisig redeemscripts and
        locktime scripts. This method is called when initializing an Input class or when signing an input.

        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int

        :return bool: Always returns True when method is completed
        """
        print("in input update")
        print("script type:", self.script_type)
        print("public hash", self.public_hash)
        print("keys", self.keys)

        unlock_script = b""

        match self.script_type:
            case "sig_pubkey" | "p2sh_p2wpkh" | "p2wpkh":
                # fixme: p2wpkh == p2sh_p2wpkh
                if not self.public_hash and self.keys:
                    self.public_hash = self.keys[0].hash160

                if not self.keys and not self.public_hash:
                    return

                self.script_code = b"\x76\xa9\x14" + self.public_hash + b"\x88\xac"
                self.unlocking_script_unsigned = self.script_code

                if self.signatures and self.keys:
                    print("we got sigs and keys yo")
                    print("sigs", self.signatures)
                    self.witnesses = [
                        self.signatures[0].as_der_encoded() if hash_type else b"",
                        self.keys[0].public_byte,
                    ]
                    print("witnesses in update", self.witnesses)
                    unlock_script = b"".join([bytes(varstr(w)) for w in self.witnesses])
                    print("unlock script", unlock_script)

                if not self.unlocking_script or self.strict:
                    self.unlocking_script = unlock_script

            # case "signature":
            #     print("in sig case")
            #     if self.keys:
            #         self.script_code = varstr(self.keys[0].public_byte) + b"\xac"
            #         self.unlocking_script_unsigned = self.script_code
            #         addr_data = self.keys[0].public_byte
            #     if self.signatures and not self.unlocking_script:
            #         self.unlocking_script = varstr(self.signatures[0].as_der_encoded())
            case _:
                raise TransactionError(
                    "Unknown unlocking script type %s for input %d"
                    % (self.script_type, self.index_n)
                )

        return True

    def verify(self, transaction_hash):
        """
        Verify input with provided transaction hash, check if signatures matches public key.

        Does not check if UTXO is valid or has already been spent

        :param transaction_hash: Double SHA256 Hash of Transaction signature
        :type transaction_hash: bytes

        :return bool: True if enough signatures provided and if all signatures are valid
        """

        if self.script_type == "coinbase":
            self.valid = True
            return True
        if not self.signatures:
            _logger.info("No signatures found for transaction input %d" % self.index_n)
            return False

        sig_n = 0
        key_n = 0
        sigs_verified = 0
        while sigs_verified < self.sigs_required:
            if key_n >= len(self.keys):
                _logger.info(
                    "Not enough valid signatures provided for input %d. Found %d signatures but %d needed"
                    % (self.index_n, sigs_verified, self.sigs_required)
                )
                return False
            if sig_n >= len(self.signatures):
                _logger.info("No valid signatures found")
                return False
            key = self.keys[key_n]
            sig = self.signatures[sig_n]
            if verify(transaction_hash, sig, key):
                sigs_verified += 1
                sig_n += 1
            elif sig_n > 0:
                # try previous signature
                prev_sig = deepcopy(self.signatures[sig_n - 1])
                if verify(transaction_hash, prev_sig, key):
                    sigs_verified += 1
            key_n += 1
        self.valid = True
        return True

    def as_dict(self):
        """
        Get transaction input information in json format

        :return dict: Json with output_n, prev_txid, output_n, type, address, public_key, public_hash, unlocking_script and sequence
        """

        pks = []
        for k in self.keys:
            pks.append(k.public_hex)
        if len(self.keys) == 1:
            pks = pks[0]
        return {
            "index_n": self.index_n,
            "prev_txid": self.outpoint.txid.hex(),
            "output_n": self.output_n_int,
            "script_type": self.script_type,
            "address": self.address,
            "value": self.value,
            "public_keys": pks,
            "compressed": self.compressed,
            "encoding": self.encoding,
            "double_spend": self.double_spend,
            "script": self.unlocking_script.hex(),
            "redeemscript": self.redeemscript.hex(),
            "sequence": self.sequence,
            "signatures": [s.hex() for s in self.signatures],
            "sigs_required": self.sigs_required,
            "locktime_cltv": self.locktime_cltv,
            "locktime_csv": self.locktime_csv,
            "public_hash": self.public_hash.hex(),
            "script_code": self.script_code.hex(),
            "unlocking_script": self.unlocking_script.hex(),
            "unlocking_script_unsigned": self.unlocking_script_unsigned.hex(),
            "witness_type": self.witness_type,
            "witness": b"".join(self.witnesses).hex(),
            "sort": self.sort,
            "valid": self.valid,
        }

    def __repr__(self):
        return (
            "<Input(prev_txid='%s', output_n=%d, address='%s', index_n=%s, type='%s')>"
            % (
                self.outpoint.txid.hex(),
                self.output_n_int,
                self.address,
                self.index_n,
                self.script_type,
            )
        )


class Output(object):
    """
    Transaction Output class, normally part of Transaction class.

    Contains the amount and destination of a transaction.
    """

    def __init__(
        self,
        value,
        address="",
        public_hash=b"",
        public_key=b"",
        lock_script=b"",
        spent=False,
        output_n=0,
        script_type="p2pkh",
        encoding="base58",
        spending_txid="",
        spending_index_n=None,
        strict=True,
        network=DEFAULT_NETWORK,
    ):
        """
        Create a new transaction output

        A transaction outputs locks the specified amount to a public key. Anyone with the private key can unlock
        this output.

        The transaction output class contains an amount and the destination which can be provided either as address,
        public key, public key hash or a locking script. Only one needs to be provided as they all can be derived
        from each other, but you can provide as many attributes as you know to improve speed.

        :param value: Amount of output in the smallest denominator integers (Satoshi's) or as Value object or string
        :type value: int, Value, str
        :param address: Destination address of output. Leave empty to derive from other attributes you provide. An instance of an Address or HDKey class is allowed as argument.
        :type address: str, Address, HDKey
        :param public_hash: Hash of public key or script
        :type public_hash: bytes, str
        :param public_key: Destination public key
        :type public_key: bytes, str
        :param lock_script: Locking script of output. If not provided a default unlocking script will be provided with a public key hash.
        :type lock_script: bytes, str
        :param spent: Is output already spent? Default is False
        :type spent: bool
        :param output_n: Output index number, default is 0. Index number has to be unique per transaction and 0 for first output, 1 for second, etc
        :type output_n: int
        :param script_type: Script type of output (p2pkh, p2sh, segwit p2wpkh, etc). Extracted from lock_script if provided.
        :type script_type: str
        :param encoding: Address encoding used. For example bech32/base32 or base58. Leave empty to derive from address or default base58 encoding
        :type encoding: str
        :param spending_txid: Transaction hash of input spending this transaction output
        :type spending_txid: str
        :param spending_index_n: Index number of input spending this transaction output
        :type spending_index_n: int
        :param strict: Raise exception when output is malformed, incomplete or not understood
        :type strict: bool
        :param network: Network, leave empty for default
        :type network: str, Network
        """

        print("output public hash param", public_hash)
        print("output address", address)

        if strict and not (address or public_hash or public_key or lock_script):
            raise TransactionError(
                "Please specify address, lock_script, public key or public key hash when "
                "creating output"
            )

        self.network = network
        if not isinstance(network, Network):
            self.network = Network(network)

        self.value = value_to_satoshi(value, network=network)

        self.lock_script = b"" if lock_script is None else to_bytes(lock_script)

        self.public_hash = to_bytes(public_hash)

        if isinstance(address, Address):
            self._address = address.address
            self._address_obj = address
        elif isinstance(address, HDKey):
            self._address = address.address()
            self._address_obj = address.address_obj
            public_key = address.public_byte
            if not script_type:
                script_type = script_type_default(
                    address.witness_type, address.multisig, True
                )
            self.public_hash = address.hash160
        else:
            self._address = address
            self._address_obj = None

        self.public_key = to_bytes(public_key)

        self.compressed = True
        self.k = None

        self.versionbyte = self.network.prefix_address
        self.script_type = script_type
        self.encoding = encoding
        self.spent = spent
        self.output_n = output_n

        print("lock scripto", self.lock_script)
        self.script = Script.parse_bytes(self.lock_script, strict=strict)

        if self._address and (
            not self.public_hash or not self.script_type or not self.encoding
        ):
            address_dict = deserialize_address(
                self._address, self.encoding, self.network.name
            )
            print(self._address)
            print(self.encoding)
            print(self.network.name)
            print("add dict", address_dict)
            if address_dict["script_type"] and not script_type:
                self.script_type = address_dict["script_type"]
            if not self.script_type:
                raise TransactionError(
                    "Could not determine script type of address %s" % self._address
                )
            self.encoding = address_dict["encoding"]
            network_guesses = address_dict["networks"]
            if address_dict["network"] and self.network.name != address_dict["network"]:
                raise TransactionError(
                    "Address %s is from %s network and transaction from %s network"
                    % (self._address, address_dict["network"], self.network.name)
                )
            elif self.network.name not in network_guesses:
                raise TransactionError(
                    "Network for output address %s is different from transaction network. %s not "
                    "in %s" % (self._address, self.network.name, network_guesses)
                )
            self.public_hash = address_dict["public_key_hash_bytes"]
            print("hash from add", self.public_hash)

        if not self.script and strict and (self.public_hash or self.public_key):
            self.script = P2PKHScript(self.public_hash)

            print("lock shit")
            print(self.script)

            self.lock_script = self.script.raw()

            if not self.script:
                raise TransactionError(
                    "Unknown output script type %s, please provide locking script"
                    % self.script_type
                )
        self.spending_txid = spending_txid
        self.spending_index_n = spending_index_n

    @property
    def address_obj(self):
        """
        Get address object property. Create standard address object if not defined already.

        :return Address:
        """
        if not self._address_obj:
            if self.public_hash:
                self._address_obj = Address(
                    hashed_data=self.public_hash,
                    script_type=self.script_type,
                    encoding=self.encoding,
                    network=self.network,
                )
                self._address = self._address_obj.address
                self.versionbyte = self._address_obj.prefix
        return self._address_obj

    @property
    def address(self):
        if not self._address:
            address_obj = self.address_obj
            if not address_obj:
                return ""
            self._address = address_obj.address
        return self._address

    @classmethod
    def parse(cls, raw, output_n=0, strict=True, network=DEFAULT_NETWORK):
        """
        Parse raw BytesIO string and return Output object

        :param raw: raw output stream
        :type raw: BytesIO
        :param output_n: Output number of Transaction output
        :type output_n: int
        :param strict: Raise exception when output is malformed, incomplete or not understood
        :type strict: bool
        :param network: Network, leave empty for default network
        :type network: str, Network

        :return Output:
        """
        value = int.from_bytes(raw.read(8)[::-1], "big")
        lock_script_size = read_varbyteint(raw)
        lock_script = raw.read(lock_script_size)
        return Output(
            value=value,
            lock_script=lock_script,
            output_n=output_n,
            strict=strict,
            network=network,
        )

    # TODO: Write and rewrite locktime methods
    # def set_locktime - CLTV (BIP65)
    # def set_locktime_blocks
    # def set_locktime_time

    def set_locktime_relative(self, locktime):
        """
        Relative timelocks with CHECKSEQUENCEVERIFY (CSV) as defined in BIP112
        :param locktime:
        :return:
        """
        pass

    def set_locktime_relative_blocks(self, blocks):
        """
        Set nSequence relative locktime for this transaction input. The transaction will only be valid if the specified number of blocks has been mined since the previous UTXO is confirmed.

        Maximum number of blocks is 65535 as defined in BIP-0068, which is around 455 days.

        When setting a relative timelock, the transaction version must be at least 2. The transaction will be updated so existing signatures for this input will be removed.

        :param blocks: The blocks value is the number of blocks since the previous transaction output has been confirmed.
        :type blocks: int

        :return None:
        """
        # if blocks == 0 or blocks == 0xffffffff:
        #     self.sequence = 0xffffffff
        #     return
        # if blocks > SEQUENCE_LOCKTIME_MASK:
        #     raise TransactionError("Number of nSequence timelock blocks exceeds %d" % SEQUENCE_LOCKTIME_MASK)
        # self.sequence = blocks
        # self.signatures = []

    def set_locktime_relative_time(self, seconds):
        """
        Set nSequence relative locktime for this transaction input. The transaction will only be valid if the specified amount of seconds have been passed since the previous UTXO is confirmed.

        Number of seconds will be rounded to the nearest 512 seconds. Any value below 512 will be interpreted as 512 seconds.

        Maximum number of seconds is 33553920 (512 * 65535), which equals 384 days. See BIP-0068 definition.

        When setting a relative timelock, the transaction version must be at least 2. The transaction will be updated so existing signatures for this input will be removed.

        :param seconds: Number of seconds since the related previous transaction output has been confirmed.
        :return:
        """
        # if seconds == 0 or seconds == 0xffffffff:
        #     self.sequence = 0xffffffff
        #     return
        # if seconds < 512:
        #     seconds = 512
        # if (seconds // 512) > SEQUENCE_LOCKTIME_MASK:
        #     raise TransactionError("Number of relative nSeqence timelock seconds exceeds %d" % SEQUENCE_LOCKTIME_MASK)
        # self.sequence = seconds // 512 + SEQUENCE_LOCKTIME_TYPE_FLAG
        # self.signatures = []

    def as_dict(self):
        """
        Get transaction output information in json format

        :return dict: Json with amount, locking script, public key, public key hash and address
        """

        return {
            "value": self.value,
            "script": self.lock_script.hex(),
            "script_type": self.script_type,
            "public_key": self.public_key.hex(),
            "public_hash": self.public_hash.hex(),
            "address": self.address,
            "output_n": self.output_n,
            "spent": self.spent,
            "spending_txid": self.spending_txid,
            "spending_index_n": self.spending_index_n,
        }

    def __repr__(self):
        return "<Output(value=%d, address=%s, type=%s)>" % (
            self.value,
            self.address,
            self.script_type,
        )


class Transaction(object):
    """
    Transaction Class

    Contains 1 or more Input class object with UTXO's to spent and 1 or more Output class objects with destinations.
    Besides the transaction class contains a locktime and version.

    Inputs and outputs can be included when creating the transaction, or can be added later with add_input and
    add_output respectively.

    A verify method is available to check if the transaction Inputs have valid unlocking scripts.

    Each input in the transaction can be signed with the sign method provided a valid private key.
    """

    @classmethod
    def parse(cls, rawtx, strict=True, network=DEFAULT_NETWORK):
        """
        Parse a raw transaction and create a Transaction object

        :param rawtx: Raw transaction string
        :type rawtx: BytesIO, bytes, str
        :param strict: Raise exception when transaction is malformed, incomplete or not understood
        :type strict: bool
        :param network: Network, leave empty for default network
        :type network: str, Network

        :return Transaction:
        """
        if isinstance(rawtx, bytes):
            rawtx = BytesIO(rawtx)
        elif isinstance(rawtx, str):
            rawtx = BytesIO(bytes.fromhex(rawtx))

        return cls.parse_bytesio(rawtx, strict, network)

    @classmethod
    def parse_bytesio(cls, rawtx, strict=True, network=DEFAULT_NETWORK):
        """
        Parse a raw transaction and create a Transaction object

        :param rawtx: Raw transaction string
        :type rawtx: BytesIO
        :param strict: Raise exception when transaction is malformed, incomplete or not understood
        :type strict: bool
        :param network: Network, leave empty for default network
        :type network: str, Network

        :return Transaction:
        """
        coinbase = False
        flag = None
        witness_type = "legacy"
        network = network
        overewintered = False
        n_version_group_id = None
        expiryheight = 0
        njoinsplit = None
        vjoinsplit = None
        joinsplitpubkey = None
        joinsplitsig = None
        if not isinstance(network, Network):
            cls.network = Network(network)
        raw_bytes = b""

        try:
            pos_start = rawtx.tell()
        except AttributeError:
            raise TransactionError(
                "Provide raw transaction as BytesIO. Use parse, parse_bytes, parse_hex to parse "
                "other data types"
            )

        header = rawtx.read(4)[::-1]
        print(header)
        le = binascii.hexlify(header)

        if int(le, 16) & (1 << 31):
            # overwinter bit set
            version = int(le, 16) & 0x7FFFFFFF
            # assert version in (3, 4)

            n_version_group_id = rawtx.read(4)[::-1]
            print(n_version_group_id)
            print(n_version_group_id[::-1])

        else:
            # v1 / v2
            version = header

        if rawtx.read(1) == b"\0":
            flag = rawtx.read(1)
            if flag == b"\1":
                witness_type = "segwit"
        else:
            rawtx.seek(-1, 1)

        n_inputs = read_varbyteint(rawtx)

        inputs = []
        print("parsebytesio", network)
        for n in range(0, n_inputs):
            inp = Input.parse(
                rawtx,
                index_n=n,
                witness_type=witness_type,
                strict=strict,
                network=network,
            )
            if inp.prev_txid == 32 * b"\0":
                coinbase = True
            print(inp.as_dict())
            inputs.append(inp)

        outputs = []
        output_total = 0
        n_outputs = read_varbyteint(rawtx)
        for n in range(0, n_outputs):
            o = Output.parse(rawtx, output_n=n, strict=strict, network=network)
            outputs.append(o)
            output_total += o.value
        if not outputs:
            raise TransactionError("Error no outputs found in this transaction")

        if witness_type == "segwit":
            for n in range(0, len(inputs)):
                n_items = read_varbyteint(rawtx)
                if not n_items:
                    continue
                script = Script()
                for m in range(0, n_items):
                    item_size = read_varbyteint(rawtx)
                    witness = rawtx.read(item_size)
                    inputs[n].witnesses.append(witness)
                    s = Script.parse_bytes(varstr(witness), strict=strict)
                    script += s

                inputs[n].script = (
                    script if not inputs[n].script else inputs[n].script + script
                )
                inputs[n].keys = script.keys
                inputs[n].signatures = script.signatures
                if (
                    script.script_types[0][:13] == "p2sh_multisig"
                    or script.script_types[0] == "signature_multisig"
                ):  # , 'p2sh_p2wsh'
                    inputs[n].script_type = "p2sh_multisig"
                    inputs[n].redeemscript = inputs[n].witnesses[-1]
                elif inputs[n].script_type == "p2wpkh":
                    inputs[n].script_type = "p2sh_p2wpkh"
                    inputs[n].witness_type = "p2sh-segwit"
                elif (
                    inputs[n].script_type == "p2wpkh"
                    or inputs[n].script_type == "p2wsh"
                ):
                    inputs[n].script_type = "p2sh_p2wsh"
                    inputs[n].witness_type = "p2sh-segwit"

                inputs[n].update_scripts()
        locktime = int.from_bytes(rawtx.read(4)[::-1], "big")
        nexpiryheight = rawtx.read(4)[::-1]
        print("nexpiryheight", binascii.hexlify(nexpiryheight))
        raw_len = len(raw_bytes)
        if not raw_bytes:
            pos_end = rawtx.tell()
            raw_len = pos_end - pos_start
            rawtx.seek(pos_start)
            raw_bytes = rawtx.read(raw_len)

        return Transaction(
            inputs,
            outputs,
            locktime,
            version,
            network,
            size=raw_len,
            output_total=output_total,
            coinbase=coinbase,
            flag=flag,
            witness_type=witness_type,
            rawtx=raw_bytes,
        )

    @classmethod
    def parse_hex(cls, rawtx, strict=True, network=DEFAULT_NETWORK):
        """
        Parse a raw hexadecimal transaction and create a Transaction object. Wrapper for the :func:`parse_bytesio`
        method

        :param rawtx: Raw transaction hexadecimal string
        :type rawtx: str
        :param strict: Raise exception when transaction is malformed, incomplete or not understood
        :type strict: bool
        :param network: Network, leave empty for default network
        :type network: str, Network

        :return Transaction:
        """
        print("parse_hex", network)

        return cls.parse_bytesio(BytesIO(bytes.fromhex(rawtx)), strict, network)

    @classmethod
    def parse_bytes(cls, rawtx, strict=True, network=DEFAULT_NETWORK):
        """
        Parse a raw bytes transaction and create a Transaction object.  Wrapper for the :func:`parse_bytesio`
        method

        :param rawtx: Raw transaction hexadecimal string
        :type rawtx: bytes
        :param strict: Raise exception when transaction is malformed, incomplete or not understood
        :type strict: bool
        :param network: Network, leave empty for default network
        :type network: str, Network

        :return Transaction:
        """

        return cls.parse(BytesIO(rawtx), strict, network)

    @staticmethod
    def load(txid=None, filename=None):
        """
        Load transaction object from file which has been stored with the :func:`save` method.

        Specify transaction ID or filename.

        :param txid: Transaction ID. Transaction object will be read from .bitcoinlib datadir
        :type txid: str
        :param filename: Name of transaction object file
        :type filename: str

        :return Transaction:
        """
        if not filename and not txid:
            raise TransactionError("Please supply filename or txid")
        elif not filename and txid:
            p = Path(BCL_DATA_DIR, "%s.tx" % txid)
        else:
            p = Path(filename)
            if not p.parent or str(p.parent) == ".":
                p = Path(BCL_DATA_DIR, filename)
        f = p.open("rb")
        t = pickle.load(f)
        f.close()
        return t

    def __init__(
        self,
        inputs=None,
        outputs=None,
        locktime=0,
        version=None,
        network=DEFAULT_NETWORK,
        fee=None,
        fee_per_kb=None,
        size=None,
        txid="",
        txhash="",
        date=None,
        confirmations=None,
        block_height=None,
        block_hash=None,
        input_total=0,
        output_total=0,
        rawtx=b"",
        status="new",
        coinbase=False,
        verified=False,
        witness_type="legacy",
        flag=None,
        overwintered=False,
        nversiongroupid=None,
        expiryheight=0,
        njoinsplit=None,
        vjoinsplit=None,
        joinsplitpubkey=None,
        joinsplitsig=None,
    ):
        """
        Create a new transaction class with provided inputs and outputs.

        You can also create an empty transaction and add input and outputs later.

        To verify and sign transactions all inputs and outputs need to be included in transaction. Any modification
        after signing makes the transaction invalid.

        :param inputs: Array of Input objects. Leave empty to add later
        :type inputs: list (Input)
        :param outputs: Array of Output object. Leave empty to add later
        :type outputs: list (Output)
        :param locktime: Transaction level locktime. Locks the transaction until a specified block (value from 1 to 5 million) or until a certain time (Timestamp in seconds after 1-jan-1970). Default value is 0 for transactions without locktime
        :type locktime: int
        :param version: Version rules. Defaults to 1 in bytes
        :type version: bytes, int
        :param network: Network, leave empty for default network
        :type network: str, Network
        :param fee: Fee in smallest denominator (ie Satoshi) for complete transaction
        :type fee: int
        :param fee_per_kb: Fee in smallest denominator per kilobyte. Specify when exact transaction size is not known.
        :type fee_per_kb: int
        :param size: Transaction size in bytes
        :type size: int
        :param txid: The transaction id (same for legacy/segwit) based on [nVersion][txins][txouts][nLockTime as hexadecimal string
        :type txid: str
        :param txhash: The transaction hash (differs from txid for witness transactions), based on [nVersion][marker][flag][txins][txouts][witness][nLockTime] in Segwit (as hexadecimal string). Unused at the moment
        :type txhash: str
        :param date: Confirmation date of transaction
        :type date: datetime
        :param confirmations: Number of confirmations
        :type confirmations: int
        :param block_height: Block number which includes transaction
        :type block_height: int
        :param block_hash: Hash of block for this transaction
        :type block_hash: str
        :param input_total: Total value of inputs
        :type input_total: int
        :param output_total: Total value of outputs
        :type output_total: int
        :param rawtx: Bytes representation of complete transaction
        :type rawtx: bytes
        :param status: Transaction status, for example: 'new', 'unconfirmed', 'confirmed'
        :type status: str
        :param coinbase: Coinbase transaction or not?
        :type coinbase: bool
        :param verified: Is transaction successfully verified? Updated when verified() method is called
        :type verified: bool
        :param witness_type: Specify witness/signature position: 'segwit' or 'legacy'. Determine from script, address or encoding if not specified.
        :type witness_type: str
        :param flag: Transaction flag to indicate version, for example for SegWit
        :type flag: bytes, str

        """
        print("motherflippin expiry", expiryheight)
        self.tx_new = LegacyTransaction(version=4)

        self.inputs = []
        print("inputs", inputs)
        if inputs is not None:
            for inp in inputs:
                self.inputs.append(inp)
            if not input_total:
                input_total = sum([i.value for i in inputs])

        id_list = [i.index_n for i in self.inputs]

        if list(dict.fromkeys(id_list)) != id_list:
            _logger.info(
                "Identical transaction indexes (tid) found in inputs, please specify unique index. "
                "Indexes will be automatically recreated"
            )
            index_n = 0
            for inp in self.inputs:
                inp.index_n = index_n
                index_n += 1

        print("outputs", outputs)
        if outputs is None:
            self.outputs = []
        else:
            self.outputs = outputs
            if not output_total:
                output_total = sum([o.value for o in outputs])

        if fee is None and output_total and input_total:
            fee = input_total - output_total
            if fee < 0 or fee == 0:
                raise TransactionError(
                    "Transaction inputs total value must be greater then total value of "
                    "transaction outputs"
                )

        if isinstance(version, int):
            if version == 4:
                self.version = b"\x80\x00\x00\x04"
                self.nversiongroupid = b"\x89/ \x85"
                self.version_int = version
            else:
                self.version = version.to_bytes(4, "big")
                self.version_int = version
        else:
            self.version = version
            self.version_int = int.from_bytes(version, "big")
        self.locktime = locktime
        self.network = network
        if not isinstance(network, Network):
            self.network = Network(network)

        # version 2/3+
        self.expiryheight = expiryheight
        self.njoinsplit = njoinsplit
        self.vjoinsplit = vjoinsplit
        self.joinsplitpubkey = joinsplitpubkey
        joinsplitsig = joinsplitsig

        self.flag = flag
        self.fee = fee
        self.fee_per_kb = fee_per_kb
        self.size = size
        self.vsize = size
        self.txid = txid
        self.txhash = txhash
        self.date = date
        self.confirmations = confirmations
        self.block_height = block_height
        self.block_hash = block_hash
        self.input_total = input_total
        self.output_total = output_total
        self.rawtx = rawtx
        self.status = status
        self.verified = verified
        self.witness_type = witness_type
        self.change = 0

        self.calc_weight_units()
        if self.witness_type not in ["legacy", "segwit"]:
            raise TransactionError(
                "Please specify a valid witness type: legacy or segwit"
            )

        print("end of init txid", self.txid)
        # this is just the hash of the tx right now, not the actual txid
        # if not self.txid:
        #     self.txid = self.signature_hash()[::-1].hex()
        # print("now txid", self.txid)
        from pprint import pprint

        pprint(self.__dict__)

    def __repr__(self):
        return "<Transaction(id=%s, inputs=%d, outputs=%d, status=%s, network=%s)>" % (
            self.txid,
            len(self.inputs),
            len(self.outputs),
            self.status,
            self.network.name,
        )

    def __str__(self):
        return self.txid

    def __add__(self, other):
        """
        Merge this transaction with another transaction keeping the original transaction intact.

        :return Transaction:
        """
        t = deepcopy(self)
        t.merge_transaction(other)
        return t

    def __hash__(self):
        return self.txid

    def __eq__(self, other):
        """
        Compare two transaction, must have same transaction ID

        :param other: Other transaction object
        :type other: Transaction

        :return bool:
        """
        if not isinstance(other, Transaction):
            raise TransactionError("Can only compare with other Transaction object")
        return self.txid == other.txid

    def as_dict(self):
        """
        Return Json dictionary with transaction information: Inputs, outputs, version and locktime

        :return dict:
        """

        inputs = []
        outputs = []
        for i in self.inputs:
            inputs.append(i.as_dict())
        for o in self.outputs:
            outputs.append(o.as_dict())
        return {
            "txid": self.txid,
            "date": self.date,
            "network": self.network.name,
            "witness_type": self.witness_type,
            "flag": None if not self.flag else ord(self.flag),
            "txhash": self.txhash,
            "confirmations": self.confirmations,
            "block_height": self.block_height,
            "block_hash": self.block_hash,
            "fee": self.fee,
            "fee_per_kb": self.fee_per_kb,
            "inputs": inputs,
            "outputs": outputs,
            "input_total": self.input_total,
            "output_total": self.output_total,
            "version": self.version_int,
            "locktime": self.locktime,
            "raw": self.raw_hex(),
            "size": self.size,
            "vsize": self.vsize,
            "verified": self.verified,
            "status": self.status,
        }

    def as_json(self):
        """
        Get current key as json formatted string

        :return str:
        """
        adict = self.as_dict()
        return json.dumps(adict, indent=4, default=str)

    def info(self):
        """
        Prints transaction information to standard output
        """

        print("Transaction %s" % self.txid)
        print("Date: %s" % self.date)
        print("Network: %s" % self.network.name)
        if self.locktime and self.locktime != 0xFFFFFFFF:
            if self.locktime < 500000000:
                print("Locktime: Until block %d" % self.locktime)
            else:
                print(
                    "Locktime: Until %s UTC" % datetime.utcfromtimestamp(self.locktime)
                )
        print("Version: %d" % self.version_int)
        print("Witness type: %s" % self.witness_type)
        print("Status: %s" % self.status)
        print("Verified: %s" % self.verified)
        print("Inputs")
        replace_by_fee = False
        for ti in self.inputs:
            print(
                "-",
                ti.address,
                Value.from_satoshi(ti.value, network=self.network).str(1),
                ti.outpoint.txid.hex(),
                ti.output_n_int,
            )
            validstr = "not validated"
            if ti.valid:
                validstr = "valid"
            elif ti.valid is False:
                validstr = "invalid"
            print(
                "  %s %s; sigs: %d (%d-of-%d) %s"
                % (
                    ti.witness_type,
                    ti.script_type,
                    len(ti.signatures),
                    ti.sigs_required or 0,
                    len(ti.keys),
                    validstr,
                )
            )
            if ti.sequence <= SEQUENCE_REPLACE_BY_FEE:
                replace_by_fee = True
            if ti.sequence <= SEQUENCE_LOCKTIME_DISABLE_FLAG:
                if ti.sequence & SEQUENCE_LOCKTIME_TYPE_FLAG:
                    print(
                        "  Relative timelock for %d seconds"
                        % (512 * (ti.sequence - SEQUENCE_LOCKTIME_TYPE_FLAG))
                    )
                else:
                    print("  Relative timelock for %d blocks" % ti.sequence)
            if ti.locktime_cltv:
                if ti.locktime_cltv & SEQUENCE_LOCKTIME_TYPE_FLAG:
                    print(
                        "  Check Locktime Verify (CLTV) for %d seconds"
                        % (512 * (ti.locktime_cltv - SEQUENCE_LOCKTIME_TYPE_FLAG))
                    )
                else:
                    print(
                        "  Check Locktime Verify (CLTV) for %d blocks"
                        % ti.locktime_cltv
                    )
            if ti.locktime_csv:
                if ti.locktime_csv & SEQUENCE_LOCKTIME_TYPE_FLAG:
                    print(
                        "  Check Sequence Verify Timelock (CSV) for %d seconds"
                        % (512 * (ti.locktime_csv - SEQUENCE_LOCKTIME_TYPE_FLAG))
                    )
                else:
                    print(
                        "  Check Sequence Verify Timelock (CSV) for %d blocks"
                        % ti.locktime_csv
                    )

        print("Outputs")
        for to in self.outputs:
            if to.script_type == "nulldata":
                print("- NULLDATA ", to.lock_script[2:])
            else:
                spent_str = ""
                if to.spent:
                    spent_str = "S"
                elif to.spent is False:
                    spent_str = "U"
                print(
                    "-",
                    to.address,
                    Value.from_satoshi(to.value, network=self.network).str(1),
                    to.script_type,
                    spent_str,
                )
        if replace_by_fee:
            print("Replace by fee: Enabled")
        print("Size: %s" % self.size)
        print("Vsize: %s" % self.vsize)
        print("Fee: %s" % self.fee)
        print("Confirmations: %s" % self.confirmations)
        print("Block: %s" % self.block_height)

    def set_locktime_relative_blocks(self, blocks, input_index_n=0):
        """
        Set nSequence relative locktime for this transaction. The transaction will only be valid if the specified number of blocks has been mined since the previous UTXO is confirmed.

        Maximum number of blocks is 65535 as defined in BIP-0068, which is around 455 days.

        When setting a relative timelock, the transaction version must be at least 2. The transaction will be updated so existing signatures for this input will be removed.

        :param blocks: The blocks value is the number of blocks since the previous transaction output has been confirmed.
        :type blocks: int
        :param input_index_n: Index number of input for nSequence locktime
        :type input_index_n: int

        :return:
        """
        if blocks == 0 or blocks == 0xFFFFFFFF:
            self.inputs[input_index_n].sequence = 0xFFFFFFFF
            self.sign(index_n=input_index_n, replace_signatures=True)
            return
        if blocks > SEQUENCE_LOCKTIME_MASK:
            raise TransactionError(
                "Number of nSequence timelock blocks exceeds %d"
                % SEQUENCE_LOCKTIME_MASK
            )
        self.inputs[input_index_n].sequence = blocks
        self.version_int = 2
        self.sign_and_update(index_n=input_index_n)

    def set_locktime_relative_time(self, seconds, input_index_n=0):
        """
        Set nSequence relative locktime for this transaction. The transaction will only be valid if the specified amount of seconds have been passed since the previous UTXO is confirmed.

        Number of seconds will be rounded to the nearest 512 seconds. Any value below 512 will be interpreted as 512 seconds.

        Maximum number of seconds is 33553920 (512 * 65535), which equals 384 days. See BIP-0068 definition.

        When setting a relative timelock, the transaction version must be at least 2. The transaction will be updated so existing signatures for this input will be removed.

        :param seconds: Number of seconds since the related previous transaction output has been confirmed.
        :type seconds: int
        :param input_index_n: Index number of input for nSequence locktime
        :type input_index_n: int

        :return:
        """
        if seconds == 0 or seconds == 0xFFFFFFFF:
            self.inputs[input_index_n].sequence = 0xFFFFFFFF
            self.sign(index_n=input_index_n, replace_signatures=True)
            return
        elif seconds < 512:
            seconds = 512
        elif (seconds // 512) > SEQUENCE_LOCKTIME_MASK:
            raise TransactionError(
                "Number of relative nSeqence timelock seconds exceeds %d"
                % SEQUENCE_LOCKTIME_MASK
            )
        self.inputs[input_index_n].sequence = (
            seconds // 512 + SEQUENCE_LOCKTIME_TYPE_FLAG
        )
        self.version_int = 2
        self.sign_and_update(index_n=input_index_n)

    def set_locktime_blocks(self, blocks):
        """
        Set nLocktime, a transaction level absolute lock time in blocks using the transaction sequence field.

        So for example if you set this value to 600000 the transaction will only be valid after block 600000.

        :param blocks: Transaction is valid after supplied block number. Value must be between 0 and 500000000. Zero means no locktime.
        :type blocks: int

        :return:
        """
        if blocks == 0 or blocks == 0xFFFFFFFF:
            self.locktime = 0xFFFFFFFF
            self.sign(replace_signatures=True)
            self.verify()
            return
        elif blocks > 500000000:
            raise TransactionError(
                "Number of locktime blocks must be below %d" % 500000000
            )
        self.locktime = blocks
        if blocks != 0 and blocks != 0xFFFFFFFF:
            for i in self.inputs:
                if i.sequence == 0xFFFFFFFF:
                    i.sequence = 0xFFFFFFFD
        self.sign_and_update()

    def set_locktime_time(self, timestamp):
        """
        Set nLocktime, a transaction level absolute lock time in timestamp using the transaction sequence field.

        :param timestamp: Transaction is valid after the given timestamp. Value must be between 500000000 and 0xfffffffe
        :return:
        """
        if timestamp == 0 or timestamp == 0xFFFFFFFF:
            self.locktime = 0xFFFFFFFF
            self.sign(replace_signatures=True)
            self.verify()
            return

        if timestamp <= 500000000:
            raise TransactionError(
                "Timestamp must have a value higher then %d" % 500000000
            )
        if timestamp > 0xFFFFFFFE:
            raise TransactionError(
                "Timestamp must have a value lower then %d" % 0xFFFFFFFE
            )
        self.locktime = timestamp

        # Input sequence value must be below 0xffffffff
        for i in self.inputs:
            if i.sequence == 0xFFFFFFFF:
                i.sequence = 0xFFFFFFFD
        self.sign_and_update()

    def signature_hash(
        self, sign_id=None, hash_type=SIGHASH_ALL, witness_type=None, as_hex=False
    ):
        """
        Double SHA256 Hash of Transaction signature

        :param sign_id: Index of input to sign
        :type sign_id: int
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int
        :param witness_type: Legacy or Segwit witness type? Leave empty to use Transaction witness type
        :type witness_type: str
        :param as_hex: Return value as hexadecimal string. Default is False
        :type as_hex: bool

        :return bytes: Transaction signature hash
        """
        print("doing signature hash")
        print(type(self.tx_new.vin[0].scriptSig))
        print((self.tx_new.vin[0].scriptSig.__dict__))
        print(binascii.hexlify(bytes(self.tx_new.vin[0].scriptSig)))
        print("txin txid", binascii.hexlify(self.tx_new.vin[0].prevout.txid))
        print("full tx", binascii.hexlify(bytes(self.tx_new)))

        # sig = self.signature(sign_id, hash_type, witness_type)
        # print("cigarillo")
        # print(binascii.hexlify(sig))
        # return double_sha256(sig, as_hex=as_hex)

        print("sign id", sign_id)
        NOT_AN_INPUT = -1
        sighash = b""
        if sign_id is not None:
            # scriptcode = b"\x76\xa9\x14" + self.public_hash + b"\x88\xac"
            print("utxo")
            print(binascii.hexlify(self.tx_new.vin[sign_id].utxoscript))
            scriptcode = self.tx_new.vin[sign_id].utxoscript
            # scriptcode = b""
            # scriptcode = self.tx_new.vin[sign_id].scriptSig

            nIn = len(self.tx_new.vin)
            print("nin", nIn)
            if nIn == 1:
                nIn = NOT_AN_INPUT
            nHashType = SIGHASH_ALL if nIn == NOT_AN_INPUT else None

            consensusBranchId = 0x76B809BB  # Sapling

            sighash = signature_hash_sapling(
                scriptcode,
                self.tx_new,
                nIn,
                nHashType,
                self.output_total,
                consensusBranchId,
            )
            print("sighash here")
            print(len(sighash))
            print(binascii.hexlify(sighash))
        return sighash

    def signature(self, sign_id=None, hash_type=SIGHASH_ALL, witness_type=None):
        """
        Serializes transaction and calculates signature for Legacy or Segwit transactions

        :param sign_id: Index of input to sign
        :type sign_id: int
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int
        :param witness_type: Legacy or Segwit witness type? Leave empty to use Transaction witness type
        :type witness_type: str

        :return bytes: Transaction signature
        """
        print("in trans sig")
        if witness_type is None:
            witness_type = self.witness_type
        if witness_type == "legacy" or sign_id is None:
            print("about to return raw")
            # return bytes(self.tx_new)
            print("blah")
            raw = self.raw(sign_id, hash_type, "legacy")
            print("in signature (raw)", raw)
            return raw
        else:
            raise TransactionError("Witness_type %s not supported" % self.witness_type)

    def raw(self, sign_id=None, hash_type=SIGHASH_ALL, witness_type=None):
        """
        Serialize raw transaction

        Return transaction with signed inputs if signatures are available

        :param sign_id: Create raw transaction which can be signed by transaction with this input ID
        :type sign_id: int, None
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int
        :param witness_type: Serialize transaction with other witness type then default. Use to create legacy raw transaction for segwit transaction to create transaction signature ID's
        :type witness_type: str

        :return bytes:
        """

        if witness_type is None:
            witness_type = self.witness_type

        r = self.version[::-1]
        if sign_id is None and witness_type == "segwit":
            r += b"\x00"  # marker (BIP 141)
            r += b"\x01"  # flag (BIP 141)

        if self.nversiongroupid:
            r += self.nversiongroupid[::-1]

        r += int_to_varbyteint(len(self.inputs))
        r_witness = b""
        for i in self.inputs:
            r += i.outpoint.txid + i.output_n[::-1]
            if i.witnesses and i.witness_type != "legacy":
                r_witness += int_to_varbyteint(len(i.witnesses)) + b"".join(
                    [bytes(varstr(w)) for w in i.witnesses]
                )
            else:
                r_witness += b"\0"
            if sign_id is None:
                print("sign id is none, using unlocking script")
                r += varstr(i.unlocking_script)
            elif sign_id == i.index_n:
                print("sign id, using unlock_script_unsigned???")
                r += varstr(i.unlocking_script_unsigned)
            else:
                r += b"\0"
            r += i.sequence.to_bytes(4, "little")

        r += int_to_varbyteint(len(self.outputs))
        for o in self.outputs:
            if o.value < 0:
                raise TransactionError("Output value < 0 not allowed")
            print("ovalue")
            print(int(o.value))
            print(binascii.hexlify(int(o.value).to_bytes(8, "little")))
            r += int(o.value).to_bytes(8, "little")
            print("varstr", binascii.hexlify(varstr(o.lock_script)))
            r += varstr(o.lock_script)

        if sign_id is None and witness_type == "segwit":
            r += r_witness

        r += self.locktime.to_bytes(4, "little")

        # this is the hex version of blockheight int, padded to 8 chars
        encoded = f"{self.expiryheight:08x}"
        expiry_bytes = bytes(encoded, "utf-8")
        # r += binascii.unhexlify(b"0013be69")[::-1]
        r += binascii.unhexlify(expiry_bytes)[::-1]

        if sign_id is not None:
            r += hash_type.to_bytes(4, "little")
        else:
            if not self.size and b"" not in [i.unlocking_script for i in self.inputs]:
                self.size = len(r)
                self.calc_weight_units()

        r += binascii.unhexlify(b"0000000000000000000000")
        print("returning raw", binascii.hexlify(r))

        return r

    def raw_hex(self, sign_id=None, hash_type=SIGHASH_ALL, witness_type=None):
        """
        Wrapper for raw() method. Return current raw transaction hex

        :param sign_id: Create raw transaction which can be signed by transaction with this input ID
        :type sign_id: int
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int
        :param witness_type: Serialize transaction with other witness type then default. Use to create legacy raw transaction for segwit transaction to create transaction signature ID's
        :type witness_type: str

        :return hexstring:
        """

        return self.raw(sign_id, hash_type=hash_type, witness_type=witness_type).hex()

    def witness_data(self):
        """
        Get witness data for all inputs of this transaction

        :return bytes:
        """
        witness_data = b""
        for i in self.inputs:
            witness_data += int_to_varbyteint(len(i.witnesses)) + b"".join(
                [bytes(varstr(w)) for w in i.witnesses]
            )
        return witness_data

    def verify(self):
        """
        Verify all inputs of a transaction, check if signatures match public key.

        Does not check if UTXO is valid or has already been spent

        :return bool: True if enough signatures provided and if all signatures are valid
        """

        self.verified = False
        for inp in self.inputs:
            try:
                transaction_hash = self.signature_hash(
                    inp.index_n, inp.hash_type, inp.witness_type
                )
            except TransactionError as e:
                _logger.info("Could not create transaction hash. Error: %s" % e)
                return False
            if not transaction_hash:
                _logger.info(
                    "Need at least 1 key to create segwit transaction signature"
                )
                return False
            self.verified = inp.verify(transaction_hash)
            if not self.verified:
                return False

        self.verified = True
        return True

    def sign(
        self,
        keys=None,
        index_n=None,
        multisig_key_n=None,
        hash_type=SIGHASH_ALL,
        fail_on_unknown_key=True,
        replace_signatures=False,
    ):
        """
        Sign the transaction input with provided private key

        :param keys: A private key or list of private keys
        :type keys: HDKey, Key, bytes, list
        :param index_n: Index of transaction input. Leave empty to sign all inputs
        :type index_n: int
        :param multisig_key_n: Index number of key for multisig input for segwit transactions. Leave empty if not known. If not specified all possibilities will be checked
        :type multisig_key_n: int
        :param hash_type: Specific hash type, default is SIGHASH_ALL
        :type hash_type: int
        :param fail_on_unknown_key: Method fails if public key from signature is not found in public key list
        :type fail_on_unknown_key: bool
        :param replace_signatures: Replace signature with new one if already signed.
        :type replace_signatures: bool

        :return None:
        """

        print("about to sign the input")
        print(keys)
        print(index_n)
        print(hash_type)

        if index_n is None:
            tids = range(len(self.inputs))
        else:
            tids = [index_n]

        for tid in tids:
            n_signs = 0
            tid_keys = [
                k
                if isinstance(k, (HDKey, Key))
                else Key(k, compressed=self.inputs[tid].compressed)
                for k in keys
            ]

            for k in self.inputs[tid].keys:
                if k.is_private and k not in tid_keys:
                    tid_keys.append(k)

            # If input does not contain any keys, try using provided keys
            if not self.inputs[tid].keys:
                self.inputs[tid].keys = tid_keys
                self.inputs[tid].update_scripts(hash_type=hash_type)

            if self.inputs[tid].script_type == "coinbase":
                raise TransactionError("Can not sign coinbase transactions")

            pub_key_list = [k.public_byte for k in self.inputs[tid].keys]
            n_total_sigs = len(self.inputs[tid].keys)
            sig_domain = [""] * n_total_sigs

            txid = self.signature_hash(tid, witness_type=self.inputs[tid].witness_type)
            print("in sign", binascii.hexlify(txid))

            for key in tid_keys:
                # Check if signature signs known key and is not already in list
                if key.public_byte not in pub_key_list:
                    if fail_on_unknown_key:
                        raise TransactionError(
                            "This key does not sign any known key: %s" % key.public_hex
                        )
                    else:
                        _logger.info(
                            "This key does not sign any known key: %s" % key.public_hex
                        )
                        continue

                if not replace_signatures and key in [
                    x.public_key for x in self.inputs[tid].signatures
                ]:
                    _logger.info("Key %s already signed" % key.public_hex)
                    break

                if not key.private_byte:
                    raise TransactionError(
                        "Please provide a valid private key to sign the transaction"
                    )
                print("private bytes", key.private_byte)
                sig = sign(txid, key)
                newsig_pos = pub_key_list.index(key.public_byte)
                sig_domain[newsig_pos] = sig
                n_signs += 1

            if not n_signs:
                break

            # Add already known signatures on correct position
            n_sigs_to_insert = len(self.inputs[tid].signatures)

            for sig in self.inputs[tid].signatures:
                if not sig.public_key:
                    break
                newsig_pos = pub_key_list.index(sig.public_key.public_byte)
                if sig_domain[newsig_pos] == "":
                    sig_domain[newsig_pos] = sig
                    n_sigs_to_insert -= 1

            if n_sigs_to_insert:
                for sig in self.inputs[tid].signatures:
                    free_positions = [i for i, s in enumerate(sig_domain) if s == ""]
                    for pos in free_positions:
                        sig_domain[pos] = sig
                        n_sigs_to_insert -= 1
                        break

            if n_sigs_to_insert:
                _logger.info(
                    "Some signatures are replaced with the signatures of the provided keys"
                )

            self.inputs[tid].signatures = [s for s in sig_domain if s != ""]
            self.inputs[tid].update_scripts(hash_type)

    def sign_and_update(self, index_n=None):
        """
        Update transaction ID and resign. Use if some properties of the transaction changed

        :param index_n: Index of transaction input. Leave empty to sign all inputs
        :type index_n: int

        :return:
        """

        print("in sign and update!!")
        self.version = self.version_int.to_bytes(4, "big")
        self.sign(index_n=index_n, replace_signatures=True)
        self.txid = self.signature_hash()[::-1].hex()
        print(self.txid)
        self.size = len(self.raw())
        self.calc_weight_units()
        self.update_totals()
        if self.fee:
            self.fee_per_kb = int((self.fee / float(self.vsize)) * 1000)

    def add_input(
        self,
        prev_txid,
        output_n,
        utxo_script,
        keys=None,
        signatures=[],
        public_hash=b"",
        unlocking_script=b"",
        unlocking_script_unsigned=None,
        script_type=None,
        address="",
        sequence=0xFFFFFFFF,
        compressed=True,
        sigs_required=None,
        sort=False,
        index_n=None,
        value=None,
        double_spend=False,
        locktime_cltv=None,
        locktime_csv=None,
        key_path="",
        witness_type=None,
        witnesses=None,
        encoding=None,
        strict=True,
    ):
        """
        Add input to this transaction

        Wrapper for append method of Input class.

        :param prev_txid: Transaction hash of the UTXO (previous output) which will be spent.
        :type prev_txid: bytes, hexstring
        :param output_n: Output number in previous transaction.
        :type output_n: bytes, int
        :param keys: Public keys can be provided to construct an Unlocking script. Optional
        :type keys: bytes, str
        :param signatures: Add signatures to input if already known
        :type signatures: bytes, str
        :param public_hash: Specify public hash from key or redeemscript if key is not available
        :type public_hash: bytes
        :param unlocking_script: Unlocking script (scriptSig) to prove ownership. Optional
        :type unlocking_script: bytes, hexstring
        :param unlocking_script_unsigned: TODO: find better name...
        :type unlocking_script_unsigned: bytes, str
        :param script_type: Type of unlocking script used, i.e. p2pkh or p2sh_multisig. Default is p2pkh
        :type script_type: str
        :param address: Specify address of input if known, default is to derive from key or scripts
        :type address: str, Address
        :param sequence: Sequence part of input, used for timelocked transactions
        :type sequence: int, bytes
        :param compressed: Use compressed or uncompressed public keys. Default is compressed
        :type compressed: bool
        :param sigs_required: Number of signatures required for a p2sh_multisig unlocking script
        :param sigs_required: int
        :param sort: Sort public keys according to BIP0045 standard. Default is False to avoid unexpected change of key order.
        :type sort: boolean
        :param index_n: Index number of position in transaction, leave empty to add input to end of inputs list
        :type index_n: int
        :param value: Value of input
        :type value: int
        :param double_spend: True if double spend is detected, depends on which service provider is selected
        :type double_spend: bool
        :param locktime_cltv: Check Lock Time Verify value. Script level absolute time lock for this input
        :type locktime_cltv: int
        :param locktime_csv: Check Sequency Verify value.
        :type locktime_csv: int
        :param key_path: Key path of input key as BIP32 string or list
        :type key_path: str, list
        :param witness_type: Specify witness/signature position: 'segwit' or 'legacy'. Determine from script, address or encoding if not specified.
        :type witness_type: str
        :param witnesses: List of witnesses for inputs, used for segwit transactions for instance.
        :type witnesses: list of bytes, list of str
        :param encoding: Address encoding used. For example bech32/base32 or base58. Leave empty to derive from script or script type
        :type encoding: str
        :param strict: Raise exception when input is malformed or incomplete
        :type strict: bool

        :return int: Transaction index number (index_n)
        """

        if index_n is None:
            index_n = len(self.inputs)
        sequence_int = sequence
        if isinstance(sequence, bytes):
            sequence_int = int.from_bytes(sequence, "little")
        if (
            self.version == b"\x00\x00\x00\x01"
            and 0 < sequence_int < SEQUENCE_LOCKTIME_DISABLE_FLAG
        ):
            self.version = b"\x00\x00\x00\x02"
            self.version_int = 2
        if witness_type is None:
            witness_type = self.witness_type

        input_new = Input(
            prev_txid=prev_txid,
            output_n=output_n,
            keys=keys,
            signatures=signatures,
            public_hash=public_hash,
            unlocking_script=unlocking_script,
            unlocking_script_unsigned=unlocking_script_unsigned,
            script_type=script_type,
            address=address,
            sequence=sequence,
            compressed=compressed,
            sigs_required=sigs_required,
            sort=sort,
            index_n=index_n,
            value=value,
            double_spend=double_spend,
            locktime_cltv=locktime_cltv,
            locktime_csv=locktime_csv,
            key_path=key_path,
            witness_type=witness_type,
            witnesses=witnesses,
            encoding=encoding,
            strict=strict,
            network=self.network.name,
            utxo_script=utxo_script,
        )
        self.tx_new.vin.append(input_new.txin)
        self.inputs.append(input_new)
        print("new input")
        print(self.tx_new.vin)
        return index_n

    def add_output(
        self,
        value,
        address="",
        public_hash=b"",
        public_key=b"",
        lock_script=b"",
        spent=False,
        output_n=None,
        encoding=None,
        spending_txid=None,
        spending_index_n=None,
        strict=True,
    ):
        """
        Add an output to this transaction

        Wrapper for the append method of the Output class.

        :param value: Value of output in the smallest denominator of currency, for example satoshi's for bitcoins
        :type value: int
        :param address: Destination address of output. Leave empty to derive from other attributes you provide.
        :type address: str, Address
        :param public_hash: Hash of public key or script
        :type public_hash: bytes, str
        :param public_key: Destination public key
        :type public_key: bytes, str
        :param lock_script: Locking script of output. If not provided a default unlocking script will be provided with a public key hash.
        :type lock_script: bytes, str
        :param spent: Has output been spent in new transaction?
        :type spent: bool, None
        :param output_n: Index number of output in transaction
        :type output_n: int
        :param encoding: Address encoding used. For example bech32/base32 or base58. Leave empty for to derive from script or script type
        :type encoding: str
        :param spending_txid: Transaction hash of input spending this transaction output
        :type spending_txid: str
        :param spending_index_n: Index number of input spending this transaction output
        :type spending_index_n: int
        :param strict: Raise exception when output is malformed or incomplete
        :type strict: bool

        :return int: Transaction output number (output_n)
        """

        print("add output address", address)
        lock_script = to_bytes(lock_script)

        if output_n is None:
            output_n = len(self.outputs)

        if not float(value).is_integer():
            raise TransactionError(
                "Output must be of type integer and contain no decimals"
            )

        if lock_script.startswith(b"\x6a"):
            if value != 0:
                raise TransactionError("Output value for OP_RETURN script must be 0")

        output_new = Output(
            value=int(value),
            address=address,
            public_hash=public_hash,
            public_key=public_key,
            lock_script=lock_script,
            spent=spent,
            output_n=output_n,
            encoding=encoding,
            spending_txid=spending_txid,
            spending_index_n=spending_index_n,
            strict=strict,
            network=self.network.name,
        )
        self.tx_new.vout.append(TxOut(int(value), output_new.script))
        print("txnew")
        print(binascii.hexlify(bytes(self.tx_new.vout[0])))
        self.outputs.append(output_new)
        return output_n

    def merge_transaction(self, transaction):
        """
        Merge this transaction with provided Transaction object.

        Add all inputs and outputs of a transaction to this Transaction object. Because the transaction signature
        changes with this operation, the transaction inputs need to be signed again.

        Can be used to implement CoinJoin. Where two or more unrelated Transactions are merged into 1 transaction
        to safe fees and increase privacy.

        :param transaction: The transaction to be merged
        :type transaction: Transaction

        """
        self.inputs += transaction.inputs
        self.outputs += transaction.outputs
        self.shuffle()
        self.update_totals()
        self.sign_and_update()

    def estimate_size(self, number_of_change_outputs=0):
        """
        Get estimated vsize in for current transaction based on transaction type and number of inputs and outputs.

        For old-style legacy transaction the vsize is the length of the transaction. In segwit transaction the
        witness data has less weight. The formula used is: math.ceil(((est_size-witness_size) * 3 + est_size) / 4)

        :param number_of_change_outputs: Number of change outputs, default is 0
        :type number_of_change_outputs: int

        :return int: Estimated transaction size
        """

        # if self.input_total and self.output_total + self.fee == self.input_total:
        #     add_change_output = False
        est_size = 10
        witness_size = 2
        if self.witness_type != "legacy":
            est_size += 2
        # TODO: if no inputs assume 1 input
        if not self.inputs:
            est_size += 125
            witness_size += 72
        for inp in self.inputs:
            est_size += 40
            scr_size = 0
            if inp.witness_type != "legacy":
                est_size += 1
            if inp.unlocking_script and len(inp.signatures) >= inp.sigs_required:
                scr_size += len(varstr(inp.unlocking_script))
                if inp.witness_type == "p2sh-segwit":
                    scr_size += sum([1 + len(w) for w in inp.witnesses])
            else:
                if inp.script_type == "sig_pubkey":
                    scr_size += 107
                    if not inp.compressed:
                        scr_size += 33
                    if inp.witness_type == "p2sh-segwit":
                        scr_size += 24
                # elif inp.script_type in ['p2sh_multisig', 'p2sh_p2wpkh', 'p2sh_p2wsh']:
                elif inp.script_type == "p2sh_multisig":
                    scr_size += 9 + (len(inp.keys) * 34) + (inp.sigs_required * 72)
                    if inp.witness_type == "p2sh-segwit":
                        scr_size += 17 * inp.sigs_required
                elif inp.script_type == "signature":
                    scr_size += 9 + 72
                else:
                    raise TransactionError(
                        "Unknown input script type %s cannot estimate transaction size"
                        % inp.script_type
                    )
            est_size += scr_size
            witness_size += scr_size
        for outp in self.outputs:
            est_size += 8
            if outp.lock_script:
                est_size += len(varstr(outp.lock_script))
            else:
                raise TransactionError(
                    "Need locking script for output %d to estimate size" % outp.output_n
                )
        if number_of_change_outputs:
            is_multisig = (
                True
                if self.inputs and self.inputs[0].script_type == "p2sh_multisig"
                else False
            )
            co_size = 8
            if not self.inputs or self.inputs[0].witness_type == "legacy":
                co_size += 24 if is_multisig else 26
            elif self.inputs[0].witness_type == "p2sh-segwit":
                co_size += 24
            else:
                co_size += 33 if is_multisig else 23
            est_size += number_of_change_outputs * co_size
        self.size = est_size
        self.vsize = est_size
        if self.witness_type == "legacy":
            return est_size
        else:
            self.vsize = math.ceil(
                (((est_size - witness_size) * 3 + est_size) / 4) - 1.5
            )
            return self.vsize

    def calc_weight_units(self):
        """
        Calculate weight units and vsize for this Transaction. Weight units are used to determine fee.

        :return int:
        """
        if not self.size:
            return None
        witness_data_size = len(self.witness_data())
        wu = self.size * 4
        if self.witness_type == "segwit" and witness_data_size > 1:
            wu = wu - 6  # for segwit marker and flag
            wu = wu - witness_data_size * 3
        self.vsize = math.ceil(wu / 4)
        return wu

    @property
    def weight_units(self):
        return self.calc_weight_units()

    def calculate_fee(self):
        """
        Get fee for this transaction in the smallest denominator (i.e. Satoshi) based on its size and the
        transaction.fee_per_kb value

        :return int: Estimated transaction fee
        """

        if not self.fee_per_kb:
            raise TransactionError(
                "Cannot calculate transaction fees: transaction.fee_per_kb is not set"
            )
        if self.fee_per_kb < self.network.fee_min:
            self.fee_per_kb = self.network.fee_min
        elif self.fee_per_kb > self.network.fee_max:
            self.fee_per_kb = self.network.fee_max
        if not self.vsize:
            self.estimate_size()
        fee = int(self.vsize / 1000.0 * self.fee_per_kb)
        return fee

    def update_totals(self):
        """
        Update input_total, output_total and fee according to inputs and outputs of this transaction

        :return int:
        """

        self.input_total = sum([i.value for i in self.inputs if i.value])
        self.output_total = sum([o.value for o in self.outputs if o.value])

        # self.fee = 0
        if self.input_total:
            self.fee = self.input_total - self.output_total
            if self.vsize:
                self.fee_per_kb = int((self.fee / float(self.vsize)) * 1000)

    def save(self, filename=None):
        """
        Store transaction object as file, so it can be imported in bitcoinlib later with the :func:`load` method.

        :param filename: Location and name of file, leave empty to store transaction in bitcoinlib data directory: .bitcoinlib/<transaction_id.tx)
        :type filename: str

        :return:
        """
        if not filename:
            p = Path(BCL_DATA_DIR, "%s.tx" % self.txid)
        else:
            p = Path(filename)
            if not p.parent or str(p.parent) == ".":
                p = Path(BCL_DATA_DIR, filename)
        f = p.open("wb")
        pickle.dump(self, f)
        f.close()

    def shuffle_inputs(self):
        """
        Shuffle transaction inputs in random order.

        :return:
        """
        random.shuffle(self.inputs)
        for idx, o in enumerate(self.inputs):
            o.index_n = idx

    def shuffle_outputs(self):
        """
        Shuffle transaction outputs in random order.

        :return:
        """
        random.shuffle(self.outputs)
        for idx, o in enumerate(self.outputs):
            o.output_n = idx

    def shuffle(self):
        """
        Shuffle transaction inputs and outputs in random order.

        :return:
        """
        self.shuffle_inputs()
        self.shuffle_outputs()
