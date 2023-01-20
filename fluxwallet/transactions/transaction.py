# -*- coding: utf-8 -*-
#
#    fluxwallet - Python Cryptocurrency Library
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

import binascii
import json
import logging
import math
import pickle
import random
from datetime import datetime
from io import BytesIO
from pathlib import Path

from fluxwallet.config.config import (
    BCL_DATA_DIR,
    DEFAULT_NETWORK,
    SEQUENCE_LOCKTIME_DISABLE_FLAG,
    SEQUENCE_LOCKTIME_MASK,
    SEQUENCE_LOCKTIME_TYPE_FLAG,
    SEQUENCE_REPLACE_BY_FEE,
    SIGHASH_ALL,
)
from fluxwallet.config.opcodes import *
from fluxwallet.encoding import (
    deepcopy,
    double_sha256,
    read_varbyteint,
    to_bytes,
    varstr,
)
from fluxwallet.keys import HDKey, Key, sign
from fluxwallet.networks import Network
from fluxwallet.scripts import Script
from fluxwallet.transactions.errors import TransactionError
from fluxwallet.transactions.inputs import Input
from fluxwallet.transactions.outputs import Output
from fluxwallet.values import Value

_logger = logging.getLogger(__name__)

from fluxwallet.transactions.transaction_new import (
    LegacyTransaction,
    TxOut,
    Script as NewScript,
    MessageScript,
    signature_hash_sapling,
)


class TransactionBuilder:
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

        header = int.from_bytes(rawtx.read(4), "little")
        overwintered = bool(header >> 31)

        if overwintered:
            version = header & 0x7FFFFFFF
            version_group_id = rawtx.read(4)[::-1].hex()

        else:
            version = header

        n_inputs = read_varbyteint(rawtx)

        inputs = []

        for n in range(0, n_inputs):
            inp = Input.parse(
                rawtx,
                index_n=n,
                witness_type=witness_type,
                strict=strict,
                network=network,
            )
            if inp.outpoint.txid == 32 * b"\0":
                coinbase = True

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

        locktime = int.from_bytes(rawtx.read(4), "little")
        expiry_height = int.from_bytes(rawtx.read(4), "little")
        value_balance = rawtx.read(8)  # should be all zero
        sighash = rawtx.read(4)[:-1]

        pos_end = rawtx.tell()
        raw_len = pos_end - pos_start
        rawtx.seek(pos_start)
        raw_bytes = rawtx.read(raw_len)
        txid = double_sha256(raw_bytes)[::-1].hex()

        return TransactionBuilder(
            txid=txid,
            inputs=inputs,
            outputs=outputs,
            locktime=locktime,
            version=version,
            # overwintered=overwintered,
            # version_group_id=version_group_id,
            expiry_height=expiry_height,
            network=network,
            size=raw_len,
            # output_total=output_total,
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

        :param txid: Transaction ID. Transaction object will be read from .fluxwallet datadir
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
        network=DEFAULT_NETWORK,
        inputs=[],
        outputs=[],
        locktime=0,
        version=4,
        coinbase=False,
        expiry_height=0,
        fee=None,
        fee_per_kb=None,
        size=None,
        txid="",
        txhash="",
        date=None,
        confirmations=None,
        block_height=None,
        block_hash=None,
        rawtx=b"",
        status="new",
        verified=False,
        witness_type="legacy",
        flag=None,
        message: str = b"",
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
        self.rawtx = rawtx
        self.tx_new = LegacyTransaction(version=version, nExpiryHeight=expiry_height)
        self.inputs = []

        if message:
            self.tx_new.vout.append(TxOut(0, MessageScript(message)))

        self.create_inputs(inputs)
        self.create_outputs(outputs)
        self.set_fee(fee)

        self.version = version
        self.locktime = locktime
        self.network = network

        if not isinstance(network, Network):
            self.network = Network(network)

        self.coinbase = coinbase
        self.expiry_height = expiry_height
        self.flag = flag
        self.fee_per_kb = fee_per_kb
        self.size = size
        self.vsize = size
        self.txid = txid
        self.txhash = txhash
        self.date = date
        self.confirmations = confirmations
        self.block_height = block_height
        self.block_hash = block_hash
        self.status = status
        self.verified = verified
        self.witness_type = witness_type
        self.change = 0

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
        if not isinstance(other, TransactionBuilder):
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
            "version": self.version,
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
        print("Version: %d" % self.version)
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
                ti.output_n,
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

        value = self.inputs[sign_id].value
        # This nIn stuff is fucked
        NOT_AN_INPUT = -1
        sighash = b""
        if sign_id is not None:
            scriptcode = self.tx_new.vin[sign_id].utxo.scriptPubKey.raw()

            nIn = len(self.tx_new.vin)
            if nIn == 1:
                nIn = NOT_AN_INPUT
            nHashType = SIGHASH_ALL if nIn == NOT_AN_INPUT else None

            consensusBranchId = 0x76B809BB  # Sapling

            sighash = signature_hash_sapling(
                scriptcode,
                self.tx_new,
                nIn,
                nHashType,
                value,
                consensusBranchId,
            )
        return sighash

    def raw(self, sign_id=None, hash_type=SIGHASH_ALL):
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
        for i in self.inputs:
            match sign_id:
                case None:
                    script = NewScript.from_bytes(i.unlocking_script)
                case i.index_n:
                    script = NewScript.from_bytes(i.unlocking_script_unsigned)
                case _:
                    script = NewScript()
            if self.tx_new.vin:
                self.tx_new.vin[i.index_n].scriptSig = script
        rawdog = bytes(self.tx_new)
        return rawdog

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

        return self.raw(sign_id, hash_type=hash_type).hex()

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

        if index_n is None:
            tids = range(len(self.inputs))
        else:
            tids = [index_n]

        for tid in tids:
            txid = self.signature_hash(tid, witness_type=self.inputs[tid].witness_type)

            # tidy this up - should only be one key (no segwit)
            key = self.inputs[tid].keys[0]

            if not key.private_byte:
                raise TransactionError(
                    "Please provide a valid private key to sign the transaction"
                )
            sig = sign(txid, key)
            self.inputs[tid].signatures = [sig]
            self.inputs[tid].update_scripts(hash_type)

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
        if self.version == 1 and 0 < sequence_int < SEQUENCE_LOCKTIME_DISABLE_FLAG:
            self.version = 2
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
        est_size = 10

        if not self.inputs:
            est_size += 125
        for inp in self.inputs:
            est_size += 40
            scr_size = 0
            if inp.unlocking_script and len(inp.signatures) >= inp.sigs_required:
                scr_size += len(varstr(inp.unlocking_script))
            else:
                if inp.script_type == "sig_pubkey":
                    scr_size += 107
                    if not inp.compressed:
                        scr_size += 33
                else:
                    raise TransactionError(
                        "Unknown input script type %s cannot estimate transaction size"
                        % inp.script_type
                    )
            est_size += scr_size
        for outp in self.outputs:
            est_size += 8
            if outp.lock_script:
                est_size += len(varstr(outp.lock_script))
            else:
                raise TransactionError(
                    "Need locking script for output %d to estimate size" % outp.output_n
                )
        if number_of_change_outputs:
            co_size = 8
            if not self.inputs or self.inputs[0].witness_type == "legacy":
                co_size += 26
            est_size += number_of_change_outputs * co_size
        self.size = est_size
        self.vsize = est_size

        return est_size

    def create_inputs(self, inputs):
        input_values = []
        for input in inputs:
            self.inputs.append(input)
            input_values.append(input.value)
        self.input_total = sum(input_values)

    def create_outputs(self, outputs):
        self.outputs = outputs
        self.output_total = sum([o.value for o in outputs])

    def set_fee(self, fee):
        if fee is None and self.output_total and self.input_total:
            fee = self.input_total - self.output_total
            if fee < 0 or fee == 0:
                raise TransactionError(
                    "Transaction inputs total value must be greater then total value of "
                    "transaction outputs"
                )
        self.fee = fee

    @property
    def weight_units(self):
        return self.size

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
        Store transaction object as file, so it can be imported in fluxwallet later with the :func:`load` method.

        :param filename: Location and name of file, leave empty to store transaction in fluxwallet data directory: .fluxwallet/<transaction_id.tx)
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
