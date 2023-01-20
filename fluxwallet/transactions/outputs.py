import logging

from fluxwallet.config.config import DEFAULT_NETWORK
from fluxwallet.encoding import read_varbyteint, to_bytes
from fluxwallet.keys import Address, HDKey, deserialize_address
from fluxwallet.networks import Network
from fluxwallet.scripts import Script, script_type_default
from fluxwallet.transactions.errors import TransactionError
from fluxwallet.transactions.transaction_new import P2PKHScript
from fluxwallet.values import value_to_satoshi

_logger = logging.getLogger(__name__)

from fluxwallet.networks import Network


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

        self.script = Script.parse_bytes(self.lock_script, strict=strict)

        if self._address and (
            not self.public_hash or not self.script_type or not self.encoding
        ):
            address_dict = deserialize_address(
                self._address, self.encoding, self.network.name
            )

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

        if not self.script and strict and (self.public_hash or self.public_key):
            self.script = P2PKHScript(self.public_hash)

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
