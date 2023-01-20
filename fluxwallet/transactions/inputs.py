import logging
from numbers import Number

from fluxwallet.config.config import DEFAULT_NETWORK, SIGHASH_ALL
from fluxwallet.encoding import (
    deepcopy,
    read_varbyteint,
    to_bytes,
    to_hexstring,
    varstr,
)
from fluxwallet.keys import Address, Signature, verify, Key
from fluxwallet.networks import Network
from fluxwallet.transactions.errors import TransactionError
from fluxwallet.transactions.transaction_new import (
    TxIn,
    UTXO,
    OutPoint,
    Script as NewScript,
)
from fluxwallet.scripts import Script

from fluxwallet.values import value_to_satoshi

import binascii

_logger = logging.getLogger(__name__)


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
        keys=[],
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
        witnesses=[],
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

        self.outpoint = OutPoint(prev_txid[::-1], output_n)
        self.utxo = UTXO(self.outpoint, NewScript.from_bytes(utxo_script))
        self.txin = TxIn(self.utxo, NewScript(), sequence)

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

        self.output_n = output_n

        self.unlocking_script = to_bytes(unlocking_script)
        self.unlocking_script_unsigned = to_bytes(unlocking_script_unsigned)

        if isinstance(sequence, Number):
            self.sequence = sequence
        else:
            self.sequence = int.from_bytes(sequence, "little")

        self.network = network

        if not isinstance(network, Network):
            self.network = Network(network)

        if isinstance(address, Address):
            self.address = address.address
            self.encoding = address.encoding
            self.network = address.network
        else:
            self.address = address

        if self.outpoint.txid == b"\0" * 32:
            self.script_type = "coinbase"

        print("new input")
        ### testing this
        if unlocking_script:
            parsed = Script.parse(unlocking_script, strict=strict)
            print(parsed)
            print("keys", parsed.keys)
            self.keys = parsed.keys
            self.address = self.keys[0].address()
            # self.signatures = self.script.signatures
            # if len(self.signatures):
            #     self.hash_type = self.signatures[0].hash_type

            # sigs_required = self.script.sigs_required
            # self.redeemscript = (
            #     self.script.redeemscript
            #     if self.script.redeemscript
            #     else self.redeemscript
            # )

            # if len(self.script.script_types) == 1 and not self.script_type:
            #     self.script_type = self.script.script_types[0]

        for key in keys:
            if not isinstance(key, Key):
                kobj = Key(key, network=network, strict=strict)
            else:
                kobj = key
            if kobj not in self.keys:
                self.compressed = kobj.compressed
                self.keys.append(kobj)
        if self.compressed is None:
            self.compressed = True
        if self.sort:
            self.keys.sort(key=lambda k: k.public_byte)
        ### testing above

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
        if len(prev_hash) != 32:
            raise TransactionError(
                "Input transaction hash not found. Probably malformed raw transaction"
            )

        output_n = int.from_bytes(raw.read(4), "little")
        unlocking_script_size = read_varbyteint(raw)
        unlocking_script = raw.read(unlocking_script_size)

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

        unlock_script = b""

        match self.script_type:
            case "sig_pubkey":
                if not self.public_hash and self.keys:
                    self.public_hash = self.keys[0].hash160

                if not self.keys and not self.public_hash:
                    return

                self.unlocking_script_unsigned = self.txin.utxo.scriptPubKey.raw()

                if self.signatures and self.keys:
                    sig = self.signatures[0].as_der_encoded() if hash_type else b""
                    self.witnesses = [sig]
                    unlock_script = bytes(varstr(sig)) + bytes(
                        varstr(self.keys[0].public_byte)
                    )

                if not self.unlocking_script or self.strict:
                    self.unlocking_script = unlock_script
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
            "output_n": self.output_n,
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
                self.output_n,
                self.address,
                self.index_n,
                self.script_type,
            )
        )
