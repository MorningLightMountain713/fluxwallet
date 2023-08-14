from __future__ import annotations

import asyncio
import logging
import random
import time
from asyncio import Queue
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from itertools import groupby
from operator import itemgetter
from typing import Sequence, Union

import numpy as np
from rich.pretty import pprint
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.exc import IntegrityError

from fluxwallet.config.config import DEFAULT_DATABASE, DEFAULT_WITNESS_TYPE
from fluxwallet.db_new import (
    Db,
    DbKey,
    DbKeyMultisigChildren,
    DbNetwork,
    DbTransaction,
    DbTransactionInput,
    DbTransactionOutput,
    DbWallet,
)
from fluxwallet.encoding import *
from fluxwallet.keys import (
    Address,
    BKeyError,
    HDKey,
    check_network_and_key,
    path_expand,
)
from fluxwallet.mnemonic import Mnemonic
from fluxwallet.networks import Network
from fluxwallet.scripts import Script
from fluxwallet.services.services import Service
from fluxwallet.transactions import (
    BaseTransaction,
    BitcoinTransaction,
    FluxTransaction,
    Input,
    Output,
    get_unlocking_script_type,
)
from fluxwallet.values import Value, value_to_satoshi
from fluxwallet.wallet import GenericTransaction, WalletTransaction
from fluxwallet.wallet.errors import WalletError
from fluxwallet.wallet.wallet_key import WalletKey

# from fluxwallet.wallet import wallet_exists

_logger = logging.getLogger(__name__)


GenericKeyType = Union[
    str,
    bytes,
    int,
    HDKey,
    WalletKey,
    list[str],
    list[bytes],
    list[int],
    list[HDKey],
    list[WalletKey],
]


def normalize_path(path: str) -> str:
    """
    Normalize BIP0044 key path for HD keys. Using single quotes for hardened keys

    >>> normalize_path("m/44h/2p/1'/0/100")
    "m/44'/2'/1'/0/100"

    :param path: BIP0044 key path
    :type path: str

    :return str: Normalized BIP0044 key path with single quotes
    """

    levels = path.split("/")
    npath = ""
    for level in levels:
        if not level:
            raise WalletError("Could not parse path. Index is empty.")
        nlevel = level
        if level[-1] in "'HhPp":
            nlevel = level[:-1] + "'"
        npath += nlevel + "/"
    if npath[-1] == "/":
        npath = npath[:-1]
    return npath


class Wallet:
    """
    Class to create and manage keys Using the BIP0044 Hierarchical Deterministic wallet definitions, so you can
    use one Masterkey to generate as much child keys as you want in a structured manner.

    You can import keys in many format such as WIF or extended WIF, bytes, hexstring, seeds or private key integer.
    For the Bitcoin network, Litecoin or any other network you define in the settings.

    Easily send and receive transactions. Compose transactions automatically or select unspent outputs.

    Each wallet name must be unique and can contain only one cointype and purpose, but practically unlimited
    accounts and addresses.
    """

    @classmethod
    async def _create(
        cls,
        name: str,
        key: HDKey,
        owner: str,
        network: str | None,
        account_id: int,
        purpose: int,
        scheme: str,
        parent_id: int,
        sort_keys: bool,
        witness_type: str,
        encoding: str,
        multisig: bool,
        sigs_required: int,
        cosigner_id: int,
        key_path: list | str | None,
        db_uri: str,
    ) -> Wallet:
        db = Db(db_uri=db_uri)

        async with db as session:
            res = await session.execute(select(DbWallet).filter_by(name=name))
            if res.first():
                raise WalletError("Wallet with name '%s' already exists" % name)
            else:
                _logger.info("Create new wallet '%s'" % name)
            if not name:
                raise WalletError("Please enter wallet name")

            if isinstance(key_path, str):
                key_path = key_path.split("/")

            key_depth = 1 if not key_path else len(key_path) - 1

            base_path = "m"
            if hasattr(key, "depth"):
                if key.depth is None:
                    key.depth = key_depth
                if key.depth > 0:
                    hardened_keys = [x for x in key_path if x[-1:] == "'"]
                    if hardened_keys:
                        depth_public_master = key_path.index(hardened_keys[-1])
                        if depth_public_master != key.depth:
                            raise WalletError(
                                "Depth of provided public master key %d does not correspond with key path "
                                "%s. Did you provide correct witness_type and multisig attribute?"
                                % (key.depth, key_path)
                            )
                    key_path = ["M"] + key_path[key.depth + 1 :]
                    base_path = "M"

            if isinstance(key_path, list):
                key_path = "/".join(key_path)

            await session.merge(DbNetwork(name=network))

            new_wallet = DbWallet(
                name=name,
                owner=owner,
                network_name=network,
                purpose=purpose,
                scheme=scheme,
                sort_keys=sort_keys,
                witness_type=witness_type,
                parent_id=parent_id,
                encoding=encoding,
                multisig=multisig,
                multisig_n_required=sigs_required,
                cosigner_id=cosigner_id,
                key_path=key_path,
            )
            session.add(new_wallet)
            await session.flush()

            new_wallet_id = new_wallet.id

            if scheme == "bip32" and multisig and parent_id is None:
                wallet = cls(new_wallet, db=db)
                await wallet.sync()

            elif scheme == "bip32":
                main_key = await WalletKey.from_hdkey(
                    name,
                    new_wallet_id,
                    session,
                    key=key,
                    network=network,
                    account_id=account_id,
                    purpose=purpose,
                    key_type="bip32",
                    encoding=encoding,
                    witness_type=witness_type,
                    multisig=multisig,
                    path=base_path,
                )
                new_wallet.main_key_id = main_key.key_id
                session.add(new_wallet)
                # await session.commit()

                wallet = cls(new_wallet, db=db, main_key=main_key.key())
                await wallet.sync()

                await wallet.key_for_path(
                    [0, 0], account_id=account_id, cosigner_id=cosigner_id
                )
            else:  # scheme == 'single':
                if not key:
                    key = HDKey(network=network, depth=key_depth)
                main_key = await WalletKey.from_hdkey(
                    name,
                    new_wallet_id,
                    session,
                    key=key,
                    network=network,
                    account_id=account_id,
                    purpose=purpose,
                    key_type="single",
                    encoding=encoding,
                    witness_type=witness_type,
                    multisig=multisig,
                )
                new_wallet.main_key_id = main_key.key_id
                session.add(new_wallet)
                wallet = cls(new_wallet, db=db, main_key=main_key.key())
                await wallet.sync()

            await session.commit()
            return wallet

    @classmethod
    async def create(
        cls,
        name: str,
        keys: GenericKeyType | None = None,
        owner: str = "",
        network: str | None = None,
        account_id: int = 0,
        purpose: int = 0,
        scheme: str = "bip32",
        sort_keys: bool = True,
        password: str = "",
        witness_type: str | None = None,
        encoding: str | None = None,
        multisig: bool | None = None,
        sigs_required: int | None = None,
        cosigner_id: int | None = None,
        key_path: list | str | None = None,
        db_uri: str | None = None,
    ) -> Wallet:
        """
        Create Wallet and insert in database. Generate masterkey or import key when specified.

        When only a name is specified a legacy Wallet with a single masterkey is created with standard p2wpkh
        scripts.

        >>> if wallet_delete_if_exists('create_legacy_wallet_test'): pass
        >>> w = Wallet.create('create_legacy_wallet_test')
        >>> w
        <Wallet(name=create_legacy_wallet_test, db_uri="None")>

        To create a multi signature wallet specify multiple keys (private or public) and provide the sigs_required
        argument if it different then len(keys)

        >>> if wallet_delete_if_exists('create_legacy_multisig_wallet_test'): pass
        >>> w = Wallet.create('create_legacy_multisig_wallet_test', keys=[HDKey(), HDKey().public()])

        To create a native segwit wallet use the option witness_type = 'segwit' and for old style addresses and p2sh
        embedded segwit script us 'ps2h-segwit' as witness_type.

        >>> if wallet_delete_if_exists('create_segwit_wallet_test'): pass
        >>> w = Wallet.create('create_segwit_wallet_test', witness_type='segwit')

        Use a masterkey WIF when creating a wallet:

        >>> wif = 'xprv9s21ZrQH143K3cxbMVswDTYgAc9CeXABQjCD9zmXCpXw4MxN93LanEARbBmV3utHZS9Db4FX1C1RbC5KSNAjQ5WNJ1dDBJ34PjfiSgRvS8x'
        >>> if wallet_delete_if_exists('fluxwallet_legacy_wallet_test', force=True): pass
        >>> w = Wallet.create('fluxwallet_legacy_wallet_test', wif)
        >>> w
        <Wallet(name=fluxwallet_legacy_wallet_test, db_uri="None")>
        >>> # Add some test utxo data:
        >>> if w.utxo_add('16QaHuFkfuebXGcYHmehRXBBX7RG9NbtLg', 100000000, '748799c9047321cb27a6320a827f1f69d767fe889c14bf11f27549638d566fe4', 0): pass

        Please mention account_id if you are using multiple accounts.

        :param name: Unique name of this Wallet
        :type name: str
        :param keys: Masterkey to or list of keys to use for this wallet. Will be automatically created if not specified. One or more keys are obligatory for multisig wallets. Can contain all key formats accepted by the HDKey object, a HDKey object or BIP39 passphrase
        :type keys: str, bytes, int, HDKey, HDWalletKey, list of str, list of bytes, list of int, list of HDKey, list of HDWalletKey
        :param owner: Wallet owner for your own reference
        :type owner: str
        :param network: Network name, use default if not specified
        :type network: str
        :param account_id: Account ID, default is 0
        :type account_id: int
        :param purpose: BIP43 purpose field, will be derived from witness_type and multisig by default
        :type purpose: int
        :param scheme: Key structure type, i.e. BIP32 or single
        :type scheme: str
        :param sort_keys: Sort keys according to BIP45 standard (used for multisig keys)
        :type sort_keys: bool
        :param password: Password to protect passphrase, only used if a passphrase is supplied in the 'key' argument.
        :type password: str
        :param witness_type: Specify witness type, default is 'legacy'. Use 'segwit' for native segregated witness wallet, or 'p2sh-segwit' for legacy compatible wallets
        :type witness_type: str
        :param encoding: Encoding used for address generation: base58 or bech32. Default is derive from wallet and/or witness type
        :type encoding: str
        :param multisig: Multisig wallet or child of a multisig wallet, default is None / derive from number of keys.
        :type multisig: bool
        :param sigs_required: Number of signatures required for validation if using a multisignature wallet. For example 2 for 2-of-3 multisignature. Default is all keys must be signed
        :type sigs_required: int
        :param cosigner_id: Set this if wallet contains only public keys, more than one private key or if you would like to create keys for other cosigners. Note: provided keys of a multisig wallet are sorted if sort_keys = True (default) so if your provided key list is not sorted the cosigned_id may be different.
        :type cosigner_id: int
        :param key_path: Key path for multisig wallet, use to create your own non-standard key path. Key path must follow the following rules:
            * Path start with masterkey (m) and end with change / address_index
            * If accounts are used, the account level must be 3. I.e.: m/purpose/coin_type/account/
            * All keys must be hardened, except for change, address_index or cosigner_id
            * Max length of path is 8 levels
        :type key_path: list, str
        :param db_uri: URI of the database
        :type db_uri: str

        :return Wallet:
        """

        if multisig is None:
            if keys and isinstance(keys, list) and len(keys) > 1:
                multisig = True
            else:
                multisig = False

        if scheme not in ["bip32", "single"]:
            raise WalletError(
                "Only bip32 or single key scheme's are supported at the moment"
            )
        if witness_type not in [None, "legacy", "p2sh-segwit", "segwit"]:
            raise WalletError(
                "Witness type %s not supported at the moment" % witness_type
            )
        if name.isdigit():
            raise WalletError(
                "Wallet name '%s' invalid, please include letter characters" % name
            )
        if multisig:
            if password:
                raise WalletError("Password protected multisig wallets not supported")
            if scheme != "bip32":
                raise WalletError(
                    "Multisig wallets should use bip32 scheme not %s" % scheme
                )
            if sigs_required is None:
                sigs_required = len(keys)
            if sigs_required > len(keys):
                raise WalletError(
                    "Number of keys required to sign is greater then number of keys provided"
                )
        elif not isinstance(keys, list):
            keys = [keys]
        if len(keys) > 15:
            raise WalletError(
                "Redeemscripts with more then 15 keys are non-standard and could result in "
                "locked up funds"
            )

        hdkey_list: list[HDKey] = []
        if keys and isinstance(keys, list) and sort_keys:
            keys.sort(key=lambda x: ("0" if isinstance(x, HDKey) else "1"))

        for key in keys:
            if isinstance(key, HDKey):
                if network and network != key.network.name:
                    raise WalletError(
                        "Network from key (%s) is different then specified network (%s)"
                        % (key.network.name, network)
                    )
                network = key.network.name
                if witness_type is None:
                    witness_type = key.witness_type
            elif key:
                # If key consists of several words assume it is a passphrase and convert it to a HDKey object
                if isinstance(key, str) and len(key.split(" ")) > 1:
                    if not network:
                        raise WalletError(
                            "Please specify network when using passphrase to create a key"
                        )
                    key = HDKey.from_seed(
                        Mnemonic().to_seed(key, password), network=network
                    )
                else:
                    try:
                        if isinstance(key, WalletKey):
                            key = key._hdkey_object
                        else:
                            key = HDKey(key, password=password, network=network)
                    except BKeyError:
                        try:
                            scheme = "single"
                            key = Address.parse(key, encoding=encoding, network=network)
                        except Exception:
                            raise WalletError("Invalid key or address: %s" % key)
                    if network is None:
                        network = key.network.name
                    if witness_type is None:
                        witness_type = key.witness_type
            hdkey_list.append(key)

        if network is None:
            network = DEFAULT_NETWORK
        if witness_type is None:
            witness_type = DEFAULT_WITNESS_TYPE
        if (
            network in ["dash", "dash_testnet", "dogecoin", "dogecoin_testnet"]
            and witness_type != "legacy"
        ):
            raise WalletError(
                "Segwit is not supported for %s wallets" % network.capitalize()
            )
        elif network in ("dogecoin", "dogecoin_testnet") and witness_type not in (
            "legacy",
            "p2sh-segwit",
        ):
            raise WalletError(
                "Pure segwit addresses are not supported for Dogecoin wallets. "
                "Please use p2sh-segwit instead"
            )

        if not key_path:
            if scheme == "single":
                key_path = ["m"]
                purpose = 0
            else:
                ks = [
                    k
                    for k in WALLET_KEY_STRUCTURES
                    if k["witness_type"] == witness_type
                    and k["multisig"] == multisig
                    and k["purpose"] is not None
                ]
                if len(ks) > 1:
                    raise WalletError(
                        "Please check definitions in WALLET_KEY_STRUCTURES. Multiple options found for "
                        "witness_type - multisig combination"
                    )
                if ks and not purpose:
                    purpose = ks[0]["purpose"]
                if ks and not encoding:
                    encoding = ks[0]["encoding"]
                key_path = ks[0]["key_path"]
        else:
            if purpose is None:
                purpose = 0
        if not encoding:
            encoding = get_encoding_from_witness(witness_type)

        if multisig:
            key = ""
        else:
            key = hdkey_list[0]

        main_key_path = key_path
        if multisig:
            if sort_keys:
                hdkey_list.sort(key=lambda x: x.public_byte)
            cos_prv_lst = [hdkey_list.index(cw) for cw in hdkey_list if cw.is_private]
            if cosigner_id is None:
                if not cos_prv_lst:
                    raise WalletError(
                        "This wallet does not contain any private keys, please specify cosigner_id for "
                        "this wallet"
                    )
                elif len(cos_prv_lst) > 1:
                    raise WalletError(
                        "This wallet contains more then 1 private key, please specify "
                        "cosigner_id for this wallet"
                    )
                cosigner_id = 0 if not cos_prv_lst else cos_prv_lst[0]
            if hdkey_list[cosigner_id].key_type == "single":
                main_key_path = "m"

        hdpm = await cls._create(
            name,
            key,
            owner=owner,
            network=network,
            account_id=account_id,
            purpose=purpose,
            scheme=scheme,
            parent_id=None,
            sort_keys=sort_keys,
            witness_type=witness_type,
            encoding=encoding,
            multisig=multisig,
            sigs_required=sigs_required,
            cosigner_id=cosigner_id,
            key_path=main_key_path,
            db_uri=db_uri,
        )

        if multisig:
            wlt_cos_id = 0
            for cokey in hdkey_list:
                if hdpm.network.name != cokey.network.name:
                    raise WalletError(
                        "Network for key %s (%s) is different then network specified: %s/%s"
                        % (
                            cokey.wif(is_private=False),
                            cokey.network.name,
                            network,
                            hdpm.network.name,
                        )
                    )
                scheme = "bip32"
                wn = name + "-cosigner-%d" % wlt_cos_id
                c_key_path = key_path
                if cokey.key_type == "single":
                    scheme = "single"
                    c_key_path = ["m"]
                w = await cls._create(
                    name=wn,
                    key=cokey,
                    owner=owner,
                    network=network,
                    account_id=account_id,
                    purpose=hdpm.purpose,
                    scheme=scheme,
                    parent_id=hdpm.wallet_id,
                    sort_keys=sort_keys,
                    witness_type=hdpm.witness_type,
                    encoding=encoding,
                    multisig=True,
                    sigs_required=None,
                    cosigner_id=wlt_cos_id,
                    key_path=c_key_path,
                    db_uri=db_uri,
                )
                hdpm.cosigner.append(w)
                wlt_cos_id += 1
        return hdpm

    @classmethod
    async def open(cls, ident: str | int, db_uri: str | None = None) -> Wallet:
        db = Db(db_uri)

        async with db as session:
            if isinstance(ident, str):
                res = await session.scalars(select(DbWallet).filter_by(name=ident))
            else:  # int
                res = await session.get(DbWallet, ident)

            db_wallet = res.first()

            if not db_wallet or not isinstance(db_wallet, DbWallet):
                raise WalletError(f"Unable to find wallet: {ident}")

        wallet = Wallet(db_wallet, db=db)
        await wallet.sync()

        return wallet

    def __enter__(self):
        return self

    def __init__(
        self,
        db_wallet: DbWallet,
        *,
        main_key: HDKey | None = None,
        db_uri: str | None = None,
        db: Db | None = None,
    ):
        """
        Open a wallet with given ID or name

        :param wallet: Wallet name or ID
        :type wallet: int, str
        :param db_uri: URI of the database
        :type db_uri: str
        :param main_key_object: Pass main key object to save time
        :type main_key_object: HDKey
        """

        self.wallet_tx_queue = Queue()

        if db:
            self.db = db
        elif db_uri:
            self.db = Db(db_uri)
        else:
            raise WalletError(
                "Unable to attach to Db, please pass in a Db instance or db_uri"
            )

        self.db_cache_uri = self.db.db_uri

        self.wallet_id = db_wallet.id

        self._name = db_wallet.name
        self._owner = db_wallet.owner

        self.network = Network(db_wallet.network_name)

        self.purpose = db_wallet.purpose
        self.scheme = db_wallet.scheme

        self._balance = None
        self._balances = []

        self.main_key_id = db_wallet.main_key_id

        self.main_key = main_key

        self._default_account_id = db_wallet.default_account_id
        self.multisig_n_required = db_wallet.multisig_n_required

        self.sort_keys = db_wallet.sort_keys

        self.providers = None
        self.witness_type = db_wallet.witness_type
        self.encoding = db_wallet.encoding
        self.multisig = db_wallet.multisig
        self.cosigner_id = db_wallet.cosigner_id

        self.script_type = script_type_default(
            self.witness_type, self.multisig, locking_script=True
        )

        self.key_path = [] if not db_wallet.key_path else db_wallet.key_path.split("/")
        self.depth_public_master = 0
        self.parent_id = db_wallet.parent_id

        self.last_scanned_height: int = 0

    # def __exit__(self, exception_type, exception_value, traceback):
    #     try:
    #         self._session.close()
    #         self._engine.dispose()
    #     except Exception:
    #         pass

    # def __del__(self):
    #     try:
    #         self._session.close()
    #         self._engine.dispose()
    #     except Exception:
    #         pass

    def __repr__(self):
        return f'<Wallet(name="{self.name}", db_uri="{self.db.db_uri}")>'

    def __str__(self):
        return self.name

    async def _get_account_defaults(
        self,
        network: str | None = None,
        account_id: int | None = None,
        key_id: int | None = None,
    ) -> tuple[str, int, DbKey]:
        """
        Check parameter values for network and account ID, return defaults if no network or account ID is specified.
        If a network is specified but no account ID this method returns the first account ID it finds.

        :param network: Network code, leave empty for default
        :type network: str
        :param account_id: Account ID, leave emtpy for default
        :type account_id: int
        :param key_id: Key ID to just update 1 key
        :type key_id: int

        :return: network code, account ID and DbKey instance of account ID key
        """
        if key_id:
            key = await self.key(key_id)

            network = key.network_name
            account_id = key.account_id

        if network is None:
            network = self.network.name

        if account_id is None and network == self.network.name:
            account_id = self.default_account_id

        async with self.db.get_session() as session:
            stmt = select(func.count(DbKey.id).label("count"), DbKey).filter_by(
                wallet_id=self.wallet_id,
                purpose=self.purpose,
                depth=self.depth_public_master,
                network_name=network,
            )

            if account_id is not None:
                stmt = stmt.filter_by(account_id=account_id)

            res = await session.execute(stmt)
            row = res.first()

        # what about if no row returned
        if row.count > 1 and "account'" in self.key_path:
            _logger.warning(
                f"No account_id specified and more than one account ({row.count}) found for this network {network}."
            )

        if account_id is None:
            if row.DbKey:
                account_id = row.DbKey.account_id
            else:
                account_id = 0

        return network, account_id, row.DbKey

    @property
    def default_account_id(self):
        return self._default_account_id

    @default_account_id.setter
    def default_account_id(self, value):
        self._default_account_id = value
        self._dbwallet = (
            self._session.query(DbWallet)
            .filter(DbWallet.id == self.wallet_id)
            .update({DbWallet.default_account_id: value})
        )
        self._commit()

    @property
    def owner(self):
        """
        Get wallet Owner

        :return str:
        """

        return self._owner

    @owner.setter
    def owner(self, value):
        """
        Set wallet Owner in database

        :param value: Owner
        :type value: str

        :return str:
        """

        self._owner = value
        self._dbwallet = (
            self._session.query(DbWallet)
            .filter(DbWallet.id == self.wallet_id)
            .update({DbWallet.owner: value})
        )
        self._commit()

    @property
    def name(self):
        """
        Get wallet name

        :return str:
        """

        return self._name

    @name.setter
    def name(self, value):
        """
        Set wallet name, update in database

        :param value: Name for this wallet
        :type value: str

        :return str:
        """

        if wallet_exists(value, db_uri=self.db.db_uri):
            raise WalletError("Wallet with name '%s' already exists" % value)
        self._name = value
        self._session.query(DbWallet).filter(DbWallet.id == self.wallet_id).update(
            {DbWallet.name: value}
        )
        self._commit()

    async def get_cosigner(self, session: AsyncSession) -> list[Wallet]:
        res = await session.scalars(
            select(DbWallet).filter_by(parent_id=self.wallet_id).order_by(DbWallet.name)
        )

        co_sign_wallets: Sequence[DbWallet] = res.all()

        return [Wallet.open(w.id, db=self.db) for w in co_sign_wallets]

    async def sync(self):
        async with self.db.get_session() as session:
            self.cosigner = await self.get_cosigner(session)

            if self.main_key_id:
                self.main_key = await WalletKey.from_db_key(
                    self.main_key_id,
                    session,
                )

            if self._default_account_id is None:
                self._default_account_id = 0
                if self.main_key:
                    self._default_account_id = self.main_key.account_id

            _logger.info("Opening wallet '%s'" % self.name)

            self._key_objects = {self.main_key_id: self.main_key}

            if self.main_key and self.main_key.depth > 0:
                self.depth_public_master = self.main_key.depth
                self.key_depth = self.depth_public_master + len(self.key_path) - 1
            else:
                hardened_keys = [x for x in self.key_path if x[-1:] == "'"]
                if hardened_keys:
                    self.depth_public_master = self.key_path.index(hardened_keys[-1])
                self.key_depth = len(self.key_path) - 1
            self.last_updated = None

    def default_network_set(self, network):
        if not isinstance(network, Network):
            network = Network(network)
        self.network = network
        self._session.query(DbWallet).filter(DbWallet.id == self.wallet_id).update(
            {DbWallet.network_name: network.name}
        )
        self._commit()

    async def import_master_key(self, hdkey, name="Masterkey (imported)"):
        """
        Import (another) masterkey in this wallet

        :param hdkey: Private key
        :type hdkey: HDKey, str
        :param name: Key name of masterkey
        :type name: str

        :return HDKey: Main key as HDKey object
        """

        network, account_id, _ = await self._get_account_defaults()
        if not isinstance(hdkey, HDKey):
            hdkey = HDKey(hdkey)
        if not isinstance(self.main_key, WalletKey):
            raise WalletError(
                "Main wallet key is not an WalletKey instance. Type %s"
                % type(self.main_key)
            )
        if not hdkey.is_private or hdkey.depth != 0:
            raise WalletError(
                "Please supply a valid private BIP32 master key with key depth 0"
            )
        if self.main_key.is_private:
            raise WalletError("Main key is already a private key, cannot import key")
        if (
            self.main_key.depth != 1
            and self.main_key.depth != 3
            and self.main_key.depth != 4
        ) or self.main_key.key_type != "bip32":
            raise WalletError("Current main key is not a valid BIP32 public master key")
        # pm = self.public_master()
        if not (self.network.name == self.main_key.network.name == hdkey.network.name):
            raise WalletError(
                "Network of Wallet class, main account key and the imported private key must use "
                "the same network"
            )
        if self.main_key.wif != hdkey.public_master().wif():
            raise WalletError(
                "This key does not correspond to current public master key"
            )

        hdkey.key_type = "bip32"
        ks = [
            k
            for k in WALLET_KEY_STRUCTURES
            if k["witness_type"] == self.witness_type
            and k["multisig"] == self.multisig
            and k["purpose"] is not None
        ]
        if len(ks) > 1:
            raise WalletError(
                "Please check definitions in WALLET_KEY_STRUCTURES. Multiple options found for "
                "witness_type - multisig combination"
            )
        self.key_path = ks[0]["key_path"]
        self.main_key = await WalletKey.from_hdkey(
            name,
            self.wallet_id,
            self._session,
            key=hdkey,
            network=network,
            account_id=account_id,
            purpose=self.purpose,
            key_type="bip32",
            witness_type=self.witness_type,
        )
        self.main_key_id = self.main_key.key_id
        self._key_objects.update({self.main_key_id: self.main_key})
        self._session.query(DbWallet).filter(DbWallet.id == self.wallet_id).update(
            {DbWallet.main_key_id: self.main_key_id}
        )

        for key in await self.keys(is_private=False):
            kp = key.path.split("/")
            if kp and kp[0] == "M":
                kp = self.key_path[: self.depth_public_master + 1] + kp[1:]
            await self.key_for_path(kp, recreate=True)

        self._commit()
        return self.main_key

    async def import_key(
        self,
        key: HDKey | Address | str | bytes | int,
        account_id: int = 0,
        name: str = "",
        network: str | None = None,
        purpose: int = 44,
        key_type: str | None = None,
    ) -> WalletKey | None:
        """
        Add new single key to wallet.

        :param key: Key to import
        :type key: str, bytes, int, HDKey, Address
        :param account_id: Account ID. Default is last used or created account ID.
        :type account_id: int
        :param name: Specify name for key, leave empty for default
        :type name: str
        :param network: Network name, method will try to extract from key if not specified. Raises warning if network could not be detected
        :type network: str
        :param purpose: BIP definition used, default is BIP44
        :type purpose: int
        :param key_type: Key type of imported key, can be single. Unrelated to wallet, bip32, bip44 or master for new or extra master key import. Default is 'single'
        :type key_type: str

        :return WalletKey:
        """

        if self.scheme not in ["bip32", "single"]:
            raise WalletError(
                "Keys can only be imported to a BIP32 or single type wallet, create a new wallet "
                "instead"
            )
        if isinstance(key, (HDKey, Address)):
            network = key.network.name
            hdkey = key

            if network not in await self.network_list():
                raise WalletError("Network %s not found in this wallet" % network)
        else:
            if isinstance(key, str) and len(key.split(" ")) > 1:
                if network is None:
                    network = self.network

                hdkey = HDKey.from_seed(Mnemonic().to_seed(key), network=network)
            else:
                if network is None:
                    network = check_network_and_key(
                        key, default_network=self.network.name
                    )
                if network not in await self.network_list():
                    raise WalletError(
                        "Network %s not available in this wallet, please create an account for this "
                        "network first." % network
                    )
                hdkey = HDKey(key, network=network, key_type=key_type)

        if not self.multisig:
            if (
                self.main_key
                and self.main_key.depth == self.depth_public_master
                and not isinstance(hdkey, Address)
                and hdkey.is_private
                and hdkey.depth == 0
                and self.scheme == "bip32"
            ):
                return self.import_master_key(hdkey, name)

            if key_type is None:
                hdkey.key_type = "single"
                key_type = "single"

            async with self.db.get_session() as session:
                ik_path = "m"
                if key_type == "single":
                    print("WIFFER", hdkey.private_byte)
                    print("NEWORK", network)
                    print("ACCOUNTID", account_id)
                    # Check if key exists
                    res = await session.scalars(
                        select(DbKey).filter(
                            DbKey.account_id == account_id,
                            DbKey.network.has(name=network),
                            DbKey.private == hdkey.private_byte,
                        )
                    )

                    key_exists = res.first()

                    print("KEY EXISTS", key_exists)

                    if key_exists:
                        return None

                    # Create path for unrelated import keys
                    hdkey.depth = self.key_depth
                    res = await session.scalars(
                        select(DbKey)
                        .filter(DbKey.path.like("import_key_%"))
                        .order_by(DbKey.path.desc())
                    )

                    last_import_key = res.first()

                    if last_import_key:
                        ik_path = "import_key_" + str(
                            int(last_import_key.path[-5:]) + 1
                        ).zfill(5)
                    else:
                        ik_path = "import_key_00001"
                    if not name:
                        name = ik_path

                mk = await WalletKey.from_hdkey(
                    name,
                    self.wallet_id,
                    session,
                    key=hdkey,
                    network=network,
                    key_type=key_type,
                    account_id=account_id,
                    purpose=purpose,
                    path=ik_path,
                    witness_type=self.witness_type,
                )

            self._key_objects.update({mk.key_id: mk})
            if mk.key_id == self.main_key.key_id:
                self.main_key = mk
            return mk
        else:
            account_key = hdkey.public_master(
                witness_type=self.witness_type, multisig=True
            ).wif()
            for w in self.cosigner:
                if w.main_key.key().wif_public() == account_key:
                    _logger.debug(
                        "Import new private cosigner key in this multisig wallet: %s"
                        % account_key
                    )
                    return w.import_master_key(hdkey)
            raise WalletError(
                "Unknown key: Can only import a private key for a known public key in multisig wallets"
            )

    def _new_key_multisig(
        self, public_keys, name, account_id, change, cosigner_id, network, address_index
    ):
        if self.sort_keys:
            public_keys.sort(key=lambda pubk: pubk.key_public)
        public_key_list = [pubk.key_public for pubk in public_keys]
        public_key_ids = [str(x.key_id) for x in public_keys]

        # Calculate redeemscript and address and add multisig key to database
        # redeemscript = serialize_multisig_redeemscript(public_key_list, n_required=self.multisig_n_required)

        # todo: pass key object, reuse key objects
        redeemscript = Script(
            script_types=["multisig"],
            keys=public_key_list,
            sigs_required=self.multisig_n_required,
        ).serialize()
        script_type = "p2sh"
        if self.witness_type == "p2sh-segwit":
            script_type = "p2sh_p2wsh"
        address = Address(
            redeemscript,
            encoding=self.encoding,
            script_type=script_type,
            network=network,
        )
        already_found_key = (
            self._session.query(DbKey)
            .filter_by(wallet_id=self.wallet_id, address=address.address)
            .first()
        )
        if already_found_key:
            return self.key(already_found_key.id)
        path = [
            pubk.path
            for pubk in public_keys
            if pubk.wallet.cosigner_id == self.cosigner_id
        ][0]
        depth = (
            self.cosigner[self.cosigner_id].main_key.depth + len(path.split("/")) - 1
        )
        if not name:
            name = "Multisig Key " + "/".join(public_key_ids)

        multisig_key = DbKey(
            name=name[:80],
            wallet_id=self.wallet_id,
            purpose=self.purpose,
            account_id=account_id,
            depth=depth,
            change=change,
            address_index=address_index,
            parent_id=0,
            is_private=False,
            path=path,
            public=address.hash_bytes,
            wif="multisig-%s" % address,
            address=address.address,
            cosigner_id=cosigner_id,
            key_type="multisig",
            network_name=network,
        )
        self._session.add(multisig_key)
        self._commit()
        for child_id in public_key_ids:
            self._session.add(
                DbKeyMultisigChildren(
                    key_order=public_key_ids.index(child_id),
                    parent_id=multisig_key.id,
                    child_id=int(child_id),
                )
            )
        self._commit()
        return self.key(multisig_key.id)

    async def new_key(
        self, name="", account_id=None, change=0, cosigner_id=None, network=None
    ) -> WalletKey:
        """
        Create a new HD Key derived from this wallet's masterkey. An account will be created for this wallet
        with index 0 if there is no account defined yet.

        >>> w = Wallet('create_legacy_wallet_test')
        >>> w.new_key('my key') # doctest:+ELLIPSIS
        <WalletKey(key_id=..., name=my key, wif=..., path=m/44'/0'/0'/0/...)>

        :param name: Key name. Does not have to be unique but if you use it at reference you might chooce to enforce this. If not specified 'Key #' with a unique sequence number will be used
        :type name: str
        :param account_id: Account ID. Default is last used or created account ID.
        :type account_id: int
        :param change: Change (1) or payments (0). Default is 0
        :type change: int
        :param cosigner_id: Cosigner ID for key path
        :type cosigner_id: int
        :param network: Network name. Leave empty for default network
        :type network: str

        :return WalletKey:
        """

        if self.scheme == "single":
            return self.main_key

        network, account_id, _ = await self._get_account_defaults(network, account_id)
        if network != self.network.name and "coin_type'" not in self.key_path:
            raise WalletError("Multiple networks not supported by wallet key structure")
        if self.multisig:
            if not self.multisig_n_required:
                raise WalletError("Multisig_n_required not set, cannot create new key")
            if cosigner_id is None:
                if self.cosigner_id is None:
                    raise WalletError(
                        "Missing Cosigner ID value, cannot create new key"
                    )
                cosigner_id = self.cosigner_id

        address_index = 0
        if (
            self.multisig
            and cosigner_id is not None
            and (
                len(self.cosigner) > cosigner_id
                and self.cosigner[cosigner_id].key_path == "m"
                or self.cosigner[cosigner_id].key_path == ["m"]
            )
        ):
            req_path = []
        else:
            async with self.db.get_session() as session:
                res = await session.scalars(
                    select(DbKey)
                    .filter_by(
                        wallet_id=self.wallet_id,
                        purpose=self.purpose,
                        network_name=network,
                        account_id=account_id,
                        change=change,
                        cosigner_id=cosigner_id,
                        depth=self.key_depth,
                    )
                    .order_by(DbKey.address_index.desc())
                )
                prevkey = res.first()

            if prevkey:
                address_index = prevkey.address_index + 1

            req_path = [change, address_index]

        return await self.key_for_path(
            req_path,
            name=name,
            account_id=account_id,
            network=network,
            cosigner_id=cosigner_id,
            address_index=address_index,
        )

    def new_key_change(self, name="", account_id=None, network=None):
        """
        Create new key to receive change for a transaction. Calls :func:`new_key` method with change=1.

        :param name: Key name. Default name is 'Change #' with an address index
        :type name: str
        :param account_id: Account ID. Default is last used or created account ID.
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str

        :return WalletKey:
        """

        return self.new_key(name=name, account_id=account_id, network=network, change=1)

    async def scan_key(
        self, key: int | WalletKey, update_confirmations: bool = True
    ) -> set[str]:
        """
        Scan for new transactions for specified wallet key and update wallet transactions

        :param key: The wallet key as object or index
        :type key: WalletKey, int

        :return bool: New transactions found?

        """

        if isinstance(key, int):
            key = await self.key(key)

        # until I fix up api stuff
        if key.network != "flux":
            return set()

        txs_found = 0
        txids_found = set()

        while True:
            new_txids = await self.transactions_update(
                key_id=key.key_id, update_confirmations=update_confirmations
            )
            new_tx_count = len(new_txids)

            _logger.info(
                "Scanned key %d, %s Found %d new transactions"
                % (key.key_id, key.address, new_tx_count)
            )

            txs_found += new_tx_count
            txids_found.update(new_txids)

            if new_tx_count < MAX_TRANSACTIONS:
                break

        return txids_found

    async def scan(
        self,
        scan_gap_limit: int = 5,
        account_id: int | None = None,
        change: bool | None = None,
        rescan_used: bool = False,
        network: str | None = None,
        keys_ignore: list[int] | None = None,
        blockcount: int | None = None,
    ) -> set[str]:
        """
        Generate new addresses/keys and scan for new transactions using the Service providers. Updates all UTXO's and balances.

        Keep scanning for new transactions until no new transactions are found for 'scan_gap_limit' addresses. Only scan keys from default network and account unless another network or account is specified.

        Use the faster :func:`utxos_update` method if you are only interested in unspent outputs.
        Use the :func:`transactions_update` method if you would like to manage the key creation yourself or if you want to scan a single key.

        :param scan_gap_limit: Amount of new keys and change keys (addresses) created for this wallet. Default is 5, so scanning stops if after 5 addresses no transaction are found.
        :type scan_gap_limit: int
        :param account_id: Account ID. Default is last used or created account ID.
        :type account_id: int
        :param change: Filter by change addresses. Set to True to include only change addresses, False to only include regular addresses. None (default) to disable filter and include both
        :type change: bool
        :param rescan_used: Rescan already used addressed. Default is False, so funds send to old addresses will be ignored by default.
        :type rescan_used: bool
        :param network: Network name. Leave empty for default network
        :type network: str
        :param keys_ignore: Id's of keys to ignore
        :type keys_ignore: list of int

        :return:
        """

        # until I fix up api stuff
        if network != "flux":
            return set()

        if not keys_ignore:
            keys_ignore = []

        background_tasks = []

        network, account_id, _ = await self._get_account_defaults(network, account_id)
        if self.scheme != "bip32" and self.scheme != "multisig" and scan_gap_limit < 2:
            raise WalletError(
                "The wallet scan() method is only available for BIP32 wallets"
            )

        srv = Service(
            network=network,
            providers=self.providers,
            cache_uri=self.db_cache_uri,
        )

        # populate cache (3 seconds)
        # this whole service thing probably needs a rewrite. As we're using websocket on the frontend,
        # we get pushed the blockheight which triggers a scan. There is no point then doing another
        # request for the blockheight as that is what triggered the scan. So have allowed this as an option
        if blockcount:
            await srv.store_blockcount(blockcount)
        else:
            blockcount = await srv.blockcount()

        print(
            f"Current height: {blockcount}, last scanned height: {self.last_scanned_height}"
        )
        if not rescan_used and not blockcount > self.last_scanned_height:
            return set()

        self.last_scanned_height = blockcount

        # Update already known transactions with known block height
        background_tasks.append(
            asyncio.create_task(self.transactions_update_confirmations())
        )

        # Rescan used addresses
        if rescan_used:
            for key in await self.keys_addresses(
                account_id=account_id, change=change, network=network, used=True
            ):
                background_tasks.append(
                    asyncio.create_task(
                        self.scan_key(key.id, update_confirmations=False)
                    )
                )

        # Check unconfirmed transactions
        async with self.db.get_session() as session:
            res = await session.scalars(
                select(DbTransaction.txid).filter(
                    DbTransaction.wallet_id == self.wallet_id,
                    DbTransaction.network_name == network,
                    DbTransaction.confirmations == 0,
                )
            )
            db_txids = res.all()

        # db_txids = [x.txid for x in db_txs]
        if db_txids:
            # start = time.perf_counter()
            # this still needs fixing... and concurrency
            background_tasks.append(
                asyncio.create_task(self.transactions_update_by_txids(db_txids))
            )
            # pprint(f"Time to update by txids: {time.perf_counter() - start}")

        # Scan each key address, stop when no new transactions are found after set scan gap limit
        if change is None:
            change_range = [0, 1]
        else:
            change_range = [change]

        counter = 0
        new_transactions = set()

        while True:
            if self.scheme == "single":
                keys_to_scan = [
                    await self.key(k.id)
                    # check this
                    for k in await self.keys_addresses()[
                        counter : counter + scan_gap_limit
                    ]
                ]
                counter += scan_gap_limit
            else:  # bip32
                # this is still ugly.
                keys_to_scan = []
                for change_type in change_range:
                    keys_to_scan.extend(
                        await self.get_keys(
                            account_id,
                            network,
                            number_of_keys=scan_gap_limit,
                            change=change_type,
                        )
                    )

            scan_tasks = []

            for key in keys_to_scan:
                if key.key_id in keys_ignore:
                    continue

                # get_keys will return the same keys so we skip if we have already scanned
                keys_ignore.append(key.key_id)

                scan_tasks.append(
                    asyncio.create_task(self.scan_key(key, update_confirmations=False))
                )

            results: list[set[str]] = await asyncio.gather(*scan_tasks)

            if not any(results):
                break

            results = set.union(*results)

            # new_transactions += sum(results)
            new_transactions.update(results)

        # make sure other tasks finish before we return
        await asyncio.gather(*background_tasks)

        return new_transactions

    async def _get_key(
        self,
        account_id=None,
        network=None,
        cosigner_id=None,
        number_of_keys=1,
        change=0,
        as_list=False,
    ) -> WalletKey:
        network, account_id, _ = await self._get_account_defaults(network, account_id)
        if cosigner_id is None:
            cosigner_id = self.cosigner_id
        elif cosigner_id > len(self.cosigner):
            raise WalletError(
                "Cosigner ID (%d) can not be greater then number of cosigners for this wallet (%d)"
                % (cosigner_id, len(self.cosigner))
            )

        async with self.db.get_session() as session:
            res = await session.scalars(
                select(DbKey.id)
                .filter_by(
                    wallet_id=self.wallet_id,
                    account_id=account_id,
                    network_name=network,
                    cosigner_id=cosigner_id,
                    used=True,
                    key_type="bip32",
                    change=change,
                    depth=self.key_depth,
                )
                .order_by(DbKey.id.desc())
            )
            last_used_key_id = res.first()

            if not last_used_key_id:
                last_used_key_id = 0

            res = await session.scalars(
                select(DbKey)
                .filter_by(
                    wallet_id=self.wallet_id,
                    account_id=account_id,
                    network_name=network,
                    cosigner_id=cosigner_id,
                    used=False,
                    key_type="bip32",
                    change=change,
                    depth=self.key_depth,
                )
                .filter(DbKey.id > last_used_key_id)
                .order_by(DbKey.id.desc())
            )
            dbkeys = res.all()

        key_list = []
        if self.scheme == "single" and len(dbkeys):
            number_of_keys = (
                len(dbkeys) if number_of_keys > len(dbkeys) else number_of_keys
            )

        for i in range(number_of_keys):
            if dbkeys:
                dk = dbkeys.pop()
                nk = await self.key(dk.id)
            else:
                nk = await self.new_key(
                    account_id=account_id,
                    change=change,
                    cosigner_id=cosigner_id,
                    network=network,
                )
            key_list.append(nk)
        if as_list:
            return key_list
        else:
            return key_list[0]

    async def get_key(
        self, account_id=None, network=None, cosigner_id=None, change=0
    ) -> WalletKey:
        """
        Get a unused key / address or create a new one with :func:`new_key` if there are no unused keys.
        Returns a key from this wallet which has no transactions linked to it.

        Use the get_keys() method to a list of unused keys. Calling the get_key() method repeatelly to receive a
        list of key doesn't work: since the key is unused it would return the same result every time you call this
        method.

        >>> w = Wallet('create_legacy_wallet_test')
        >>> w.get_key() # doctest:+ELLIPSIS
        <WalletKey(key_id=..., name=..., wif=..., path=m/44'/0'/0'/0/...)>

        :param account_id: Account ID. Default is last used or created account ID.
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param cosigner_id: Cosigner ID for key path
        :type cosigner_id: int
        :param change: Payment (0) or change key (1). Default is 0
        :type change: int

        :return WalletKey:
        """
        return await self._get_key(
            account_id, network, cosigner_id, change=change, as_list=False
        )

    async def get_keys(
        self,
        account_id=None,
        network=None,
        cosigner_id=None,
        number_of_keys=1,
        change=0,
    ):
        """
        Get a list of unused keys / addresses or create a new ones with :func:`new_key` if there are no unused keys.
        Returns a list of keys from this wallet which has no transactions linked to it.

        Use the get_key() method to get a single key.

        :param account_id: Account ID. Default is last used or created account ID.
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param cosigner_id: Cosigner ID for key path
        :type cosigner_id: int
        :param number_of_keys: Number of keys to return. Default is 1
        :type number_of_keys: int
        :param change: Payment (0) or change key (1). Default is 0
        :type change: int

        :return list of WalletKey:
        """
        if self.scheme == "single":
            raise WalletError(
                "Single wallet has only one (master)key. Use get_key() or main_key() method"
            )
        return await self._get_key(
            account_id, network, cosigner_id, number_of_keys, change, as_list=True
        )

    def get_key_change(self, account_id=None, network=None):
        """
        Get a unused change key or create a new one if there are no unused keys.
        Wrapper for the :func:`get_key` method

        :param account_id: Account ID. Default is last used or created account ID.
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str

        :return WalletKey:
        """

        return self._get_key(
            account_id=account_id, network=network, change=1, as_list=False
        )

    def get_keys_change(self, account_id=None, network=None, number_of_keys=1):
        """
        Get a unused change key or create a new one if there are no unused keys.
        Wrapper for the :func:`get_key` method

        :param account_id: Account ID. Default is last used or created account ID.
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param number_of_keys: Number of keys to return. Default is 1
        :type number_of_keys: int

        :return list of WalletKey:
        """

        return self._get_key(
            account_id=account_id,
            network=network,
            change=1,
            number_of_keys=number_of_keys,
            as_list=True,
        )

    async def new_account(self, name="", account_id=None, network=None):
        """
        Create a new account with a child key for payments and 1 for change.

        An account key can only be created if wallet contains a masterkey.

        :param name: Account Name. If not specified "Account #" with the account_id will be used as name
        :type name: str
        :param account_id: Account ID. Default is last accounts ID + 1
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str

        :return WalletKey:
        """

        if self.scheme != "bip32":
            raise WalletError(
                "We can only create new accounts for a wallet with a BIP32 key scheme"
            )
        if self.main_key and (
            self.main_key.depth != 0 or self.main_key.is_private is False
        ):
            raise WalletError(
                "A master private key of depth 0 is needed to create new accounts (depth: %d)"
                % self.main_key.depth
            )
        if "account'" not in self.key_path:
            raise WalletError(
                "Accounts are not supported for this wallet. Account not found in key path %s"
                % self.key_path
            )
        if network is None:
            network = self.network.name
        elif network != self.network.name and "coin_type'" not in self.key_path:
            raise WalletError("Multiple networks not supported by wallet key structure")

        duplicate_cointypes = [
            Network(x).name
            for x in await self.network_list()
            if Network(x).name != network
            and Network(x).bip44_cointype == Network(network).bip44_cointype
        ]
        if duplicate_cointypes:
            raise WalletError(
                "Can not create new account for network %s with same BIP44 cointype: %s"
                % (network, duplicate_cointypes)
            )

        # Determine account_id and name
        if account_id is None:
            account_id = 0
            qr = (
                self._session.query(DbKey)
                .filter_by(
                    wallet_id=self.wallet_id, purpose=self.purpose, network_name=network
                )
                .order_by(DbKey.account_id.desc())
                .first()
            )
            if qr:
                account_id = qr.account_id + 1
        if await self.keys(
            account_id=account_id, depth=self.depth_public_master, network=network
        ):
            raise WalletError(
                "Account with ID %d already exists for this wallet" % account_id
            )

        acckey = await self.key_for_path(
            [],
            level_offset=self.depth_public_master - self.key_depth,
            account_id=account_id,
            name=name,
            network=network,
        )
        await self.key_for_path([0, 0], network=network, account_id=account_id)
        await self.key_for_path([1, 0], network=network, account_id=account_id)
        return acckey

    async def path_expand(
        self,
        path,
        level_offset=None,
        account_id=None,
        cosigner_id=0,
        address_index=None,
        change=0,
        network=DEFAULT_NETWORK,
    ):
        """
        Create key path. Specify part of key path to expand to key path used in this wallet.

        >>> w = Wallet('create_legacy_wallet_test')
        >>> w.path_expand([0,1200])
        ['m', "44'", "0'", "0'", '0', '1200']

        >>> w = Wallet('create_legacy_multisig_wallet_test')
        >>> w.path_expand([0,2], cosigner_id=1)
        ['m', "45'", '1', '0', '2']

        :param path: Part of path, for example [0, 2] for change=0 and address_index=2
        :type path: list, str
        :param level_offset: Just create part of path. For example -2 means create path with the last 2 items (change, address_index) or 1 will return the master key 'm'
        :type level_offset: int
        :param account_id: Account ID
        :type account_id: int
        :param cosigner_id: ID of cosigner
        :type cosigner_id: int
        :param address_index: Index of key, normally provided to 'path' argument
        :type address_index: int
        :param change: Change key = 1 or normal = 0, normally provided to 'path' argument
        :type change: int
        :param network: Network name. Leave empty for default network
        :type network: str

        :return list:
        """
        network, account_id, _ = await self._get_account_defaults(network, account_id)
        return path_expand(
            path,
            self.key_path,
            level_offset,
            account_id=account_id,
            cosigner_id=cosigner_id,
            address_index=address_index,
            change=change,
            purpose=self.purpose,
            witness_type=self.witness_type,
            network=network,
        )

    async def key_for_path(
        self,
        path,
        level_offset=None,
        name=None,
        account_id=None,
        cosigner_id=None,
        address_index=0,
        change=0,
        network=None,
        recreate=False,
    ) -> WalletKey | None:
        """
        Return key for specified path. Derive all wallet keys in path if they not already exists

        >>> w = wallet_create_or_open('key_for_path_example')
        >>> key = w.key_for_path([0, 0])
        >>> key.path
        "m/44'/0'/0'/0/0"

        >>> w.key_for_path([], level_offset=-2).path
        "m/44'/0'/0'"

        >>> w.key_for_path([], w.depth_public_master + 1).path
        "m/44'/0'/0'"

        Arguments provided in 'path' take precedence over other arguments. The address_index argument is ignored:
        >>> key = w.key_for_path([0, 10], address_index=1000)
        >>> key.path
        "m/44'/0'/0'/0/10"
        >>> key.address_index
        10

        :param path: Part of key path, i.e. [0, 0] for [change=0, address_index=0]
        :type path: list, str
        :param level_offset: Just create part of path, when creating keys. For example -2 means create path with the last 2 items (change, address_index) or 1 will return the master key 'm'
        :type level_offset: int
        :param name: Specify key name for latest/highest key in structure
        :type name: str
        :param account_id: Account ID
        :type account_id: int
        :param cosigner_id: ID of cosigner
        :type cosigner_id: int
        :param address_index: Index of key, normally provided to 'path' argument
        :type address_index: int
        :param change: Change key = 1 or normal = 0, normally provided to 'path' argument
        :type change: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param recreate: Recreate key, even if already found in wallet. Can be used to update public key with private key info
        :type recreate: bool

        :return WalletKey:
        """

        network, account_id, _ = await self._get_account_defaults(network, account_id)
        cosigner_id = cosigner_id if cosigner_id is not None else self.cosigner_id

        level_offset_key = level_offset
        if level_offset and self.main_key and level_offset > 0:
            level_offset_key = level_offset - self.main_key.depth

        key_path = self.key_path
        if (
            self.multisig
            and cosigner_id is not None
            and len(self.cosigner) > cosigner_id
        ):
            key_path = self.cosigner[cosigner_id].key_path

        fullpath = path_expand(
            path,
            key_path,
            level_offset_key,
            account_id=account_id,
            cosigner_id=cosigner_id,
            purpose=self.purpose,
            address_index=address_index,
            change=change,
            witness_type=self.witness_type,
            network=network,
        )

        if self.multisig and self.cosigner:
            public_keys = []
            for wlt in self.cosigner:
                if wlt.scheme == "single":
                    wk = wlt.main_key
                else:
                    wk = await wlt.key_for_path(
                        path,
                        level_offset=level_offset,
                        account_id=account_id,
                        name=name,
                        cosigner_id=cosigner_id,
                        network=network,
                        recreate=recreate,
                    )
                public_keys.append(wk)

            return await self._new_key_multisig(
                public_keys,
                name,
                account_id,
                change,
                cosigner_id,
                network,
                address_index,
            )

        # Check for closest ancestor in wallet
        wpath = fullpath
        if self.main_key.depth and fullpath and fullpath[0] != "M":
            wpath = ["M"] + fullpath[self.main_key.depth + 1 :]

        dbkey = None
        async with self.db.get_session() as session:
            while wpath and not dbkey:
                stmt = select(DbKey).filter_by(
                    path=normalize_path("/".join(wpath)), wallet_id=self.wallet_id
                )
                if recreate:
                    stmt = stmt.filter_by(is_private=True)
                res = await session.scalars(stmt)
                dbkey = res.first()
                wpath = wpath[:-1]

        if not dbkey:
            _logger.warning("No master or public master key found in this wallet")
            return None
        else:
            topkey = await self.key(dbkey.id)

        # Key already found in db, return key
        if dbkey and dbkey.path == normalize_path("/".join(fullpath)) and not recreate:
            return topkey
        else:
            # Create 1 or more keys add them to wallet
            nk = None
            parent_id = topkey.key_id
            ck = topkey.key()
            newpath = topkey.path
            n_items = len(str(dbkey.path).split("/"))
            for lvl in fullpath[n_items:]:
                ck = ck.subkey_for_path(lvl, network=network)
                newpath += "/" + lvl
                if not account_id:
                    account_id = (
                        0
                        if "account'" not in self.key_path
                        or self.key_path.index("account'") >= len(fullpath)
                        else int(fullpath[self.key_path.index("account'")][:-1])
                    )
                change = (
                    None
                    if "change" not in self.key_path
                    or self.key_path.index("change") >= len(fullpath)
                    else int(fullpath[self.key_path.index("change")])
                )
                if name and len(fullpath) == len(newpath.split("/")):
                    key_name = name
                else:
                    key_name = "%s %s" % (
                        self.key_path[len(newpath.split("/")) - 1],
                        lvl,
                    )
                    key_name = key_name.replace("'", "").replace("_", " ")

                nk = await WalletKey.from_hdkey(
                    key_name,
                    self.wallet_id,
                    session,
                    key=ck,
                    account_id=account_id,
                    change=change,
                    purpose=self.purpose,
                    path=newpath,
                    parent_id=parent_id,
                    encoding=self.encoding,
                    witness_type=self.witness_type,
                    cosigner_id=cosigner_id,
                    network=network,
                )
                self._key_objects.update({nk.key_id: nk})
                parent_id = nk.key_id
            return nk

    async def keys(
        self,
        account_id: int | None = None,
        name: str | None = None,
        key_id: int | None = None,
        change: int | None = None,
        depth: int | None = None,
        used: bool | None = None,
        is_private: bool | None = None,
        has_balance: bool | None = None,
        is_active: bool | None = None,
        network: str | None = None,
        include_private: bool | None = False,
        as_dict: bool = False,
        eager_load_network: bool = False,
    ) -> list[DbKey]:
        """
        Search for keys in database. Include 0 or more of account_id, name, key_id, change and depth.

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> all_wallet_keys = w.keys()
        >>> w.keys(depth=0) # doctest:+ELLIPSIS
        [<DbKey(id=..., name='fluxwallet_legacy_wallet_test', wif='xprv9s21ZrQH143K3cxbMVswDTYgAc9CeXABQjCD9zmXCpXw4MxN93LanEARbBmV3utHZS9Db4FX1C1RbC5KSNAjQ5WNJ1dDBJ34PjfiSgRvS8x'>]

        Returns a list of DbKey object or dictionary object if as_dict is True

        :param account_id: Search for account ID
        :type account_id: int
        :param name: Search for Name
        :type name: str
        :param key_id: Search for Key ID
        :type key_id: int
        :param change: Search for Change
        :type change: int
        :param depth: Only include keys with this depth
        :type depth: int
        :param used: Only return used or unused keys
        :type used: bool
        :param is_private: Only return private keys
        :type is_private: bool
        :param has_balance: Only include keys with a balance or without a balance, default is both
        :type has_balance: bool
        :param is_active: Hide inactive keys. Only include active keys with either a balance or which are unused, default is None (show all)
        :type is_active: bool
        :param network: Network name filter
        :type network: str
        :param include_private: Include private key information in dictionary
        :type include_private: bool
        :param as_dict: Return keys as dictionary objects. Default is False: DbKey objects
        :type as_dict: bool

        :return list of DbKey: List of Keys
        """
        async with self.db.get_session() as session:
            stmt = select(DbKey).filter_by(wallet_id=self.wallet_id).order_by(DbKey.id)
            if network is not None:
                stmt = stmt.filter(DbKey.network_name == network)
            if account_id is not None:
                stmt = stmt.filter(DbKey.account_id == account_id)
                if self.scheme == "bip32" and depth is None:
                    stmt = stmt.filter(DbKey.depth >= 3)
            if change is not None:
                stmt = stmt.filter(DbKey.change == change)
                if self.scheme == "bip32" and depth is None:
                    stmt = stmt.filter(DbKey.depth > self.key_depth - 1)
            if depth is not None:
                stmt = stmt.filter(DbKey.depth == depth)
            if name is not None:
                stmt = stmt.filter(DbKey.name == name)
            if key_id is not None:
                stmt = stmt.filter(DbKey.id == key_id)
                is_active = False
            elif used is not None:
                stmt = stmt.filter(DbKey.used == used)
            if is_private is not None:
                stmt = stmt.filter(DbKey.is_private == is_private)
            if has_balance is True and is_active is True:
                raise WalletError(
                    "Cannot use has_balance and is_active parameter together"
                )
            if has_balance is not None:
                if has_balance:
                    stmt = stmt.filter(DbKey.balance != 0)
                else:
                    stmt = stmt.filter(DbKey.balance == 0)
            if is_active:  # Unused keys and keys with a balance
                stmt = stmt.filter(or_(DbKey.balance != 0, DbKey.used.is_(False)))

            res = await session.scalars(stmt.order_by(DbKey.depth))
            keys = res.all()

            if eager_load_network:
                for key in keys:
                    await key.awaitable_attrs.network

        if as_dict:
            keys = [x.__dict__ for x in keys]
            keys2 = []
            private_fields = []
            if not include_private:
                private_fields += ["private", "wif"]
            for key in keys:
                keys2.append(
                    {
                        k: v
                        for (k, v) in key.items()
                        if k[:1] != "_" and k != "wallet" and k not in private_fields
                    }
                )
            return keys2

        return keys

    async def keys_networks(
        self, used: bool | None = None, as_dict: bool = False
    ) -> list[DbKey]:
        """
        Get keys of defined networks for this wallet. Wrapper for the :func:`keys` method

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> network_key = w.keys_networks()
        >>> # Address index of hardened key 0' is 2147483648
        >>> network_key[0].address_index
        2147483648
        >>> network_key[0].path
        "m/44'/0'"

        :param used: Only return used or unused keys
        :type used: bool
        :param as_dict: Return as dictionary or DbKey object. Default is False: DbKey objects
        :type as_dict: bool

        :return list of (DbKey, dict):

        """

        if self.scheme != "bip32":
            raise WalletError(
                "The 'keys_network' method can only be used with BIP32 type wallets"
            )
        try:
            depth = self.key_path.index("coin_type'")
        except ValueError:
            return []
        if self.multisig and self.cosigner:
            _logger.warning(
                "No network keys available for multisig wallet, use networks() method for list of networks"
            )

        return await self.keys(
            depth=depth, used=used, as_dict=as_dict, eager_load_network=True
        )

    async def keys_accounts(
        self, account_id=None, network=DEFAULT_NETWORK, as_dict=False
    ):
        """
        Get Database records of account key(s) with for current wallet. Wrapper for the :func:`keys` method.

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> account_key = w.keys_accounts()
        >>> account_key[0].path
        "m/44'/0'/0'"

        Returns nothing if no account keys are available for instance in multisig or single account wallets. In this case use :func:`accounts` method instead.

        :param account_id: Search for Account ID
        :type account_id: int
        :param network: Network name filter
        :type network: str
        :param as_dict: Return as dictionary or DbKey object. Default is False: DbKey objects
        :type as_dict: bool

        :return list of (DbKey, dict):
        """

        return await self.keys(
            account_id, depth=self.depth_public_master, network=network, as_dict=as_dict
        )

    async def keys_addresses(
        self,
        account_id=None,
        used=None,
        is_active=None,
        change=None,
        network=None,
        depth=None,
        as_dict=False,
    ):
        """
        Get address keys of specified account_id for current wallet. Wrapper for the :func:`keys` methods.

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> w.keys_addresses()[0].address
        '16QaHuFkfuebXGcYHmehRXBBX7RG9NbtLg'

        :param account_id: Account ID
        :type account_id: int
        :param used: Only return used or unused keys
        :type used: bool
        :param is_active: Hide inactive keys. Only include active keys with either a balance or which are unused, default is True
        :type is_active: bool
        :param change: Search for Change
        :type change: int
        :param network: Network name filter
        :type network: str
        :param depth: Filter by key depth. Default for BIP44 and multisig is 5
        :type depth: int
        :param as_dict: Return as dictionary or DbKey object. Default is False: DbKey objects
        :type as_dict: bool

        :return list of (DbKey, dict)
        """

        if depth is None:
            depth = self.key_depth
        return await self.keys(
            account_id,
            depth=depth,
            used=used,
            change=change,
            is_active=is_active,
            network=network,
            as_dict=as_dict,
        )

    async def keys_address_payment(
        self, account_id=None, used=None, network=None, as_dict=False
    ):
        """
        Get payment addresses (change=0) of specified account_id for current wallet. Wrapper for the :func:`keys` methods.

        :param account_id: Account ID
        :type account_id: int
        :param used: Only return used or unused keys
        :type used: bool
        :param network: Network name filter
        :type network: str
        :param as_dict: Return as dictionary or DbKey object. Default is False: DbKey objects
        :type as_dict: bool

        :return list of (DbKey, dict)
        """

        return await self.keys(
            account_id,
            depth=self.key_depth,
            change=0,
            used=used,
            network=network,
            as_dict=as_dict,
        )

    async def keys_address_change(
        self, account_id=None, used=None, network=None, as_dict=False
    ):
        """
        Get payment addresses (change=1) of specified account_id for current wallet. Wrapper for the :func:`keys` methods.

        :param account_id: Account ID
        :type account_id: int
        :param used: Only return used or unused keys
        :type used: bool
        :param network: Network name filter
        :type network: str
        :param as_dict: Return as dictionary or DbKey object. Default is False: DbKey objects
        :type as_dict: bool

        :return list of (DbKey, dict)
        """

        return await self.keys(
            account_id,
            depth=self.key_depth,
            change=1,
            used=used,
            network=network,
            as_dict=as_dict,
        )

    async def addresslist(
        self,
        account_id=None,
        used=None,
        network=None,
        change=None,
        depth=None,
        key_id=None,
    ) -> list[str]:
        """
        Get list of addresses defined in current wallet. Wrapper for the :func:`keys` methods.

        Use :func:`keys_addresses` method to receive full key objects

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> w.addresslist()[0]
        '16QaHuFkfuebXGcYHmehRXBBX7RG9NbtLg'

        :param account_id: Account ID
        :type account_id: int
        :param used: Only return used or unused keys
        :type used: bool, None
        :param network: Network name filter
        :type network: str
        :param change: Only include change addresses or not. Default is None which returns both
        :param depth: Filter by key depth. Default is None for standard key depth. Use -1 to show all keys
        :type depth: int
        :param key_id: Key ID to get address of just 1 key
        :type key_id: int

        :return list of str: List of address strings
        """

        addresslist = []
        if depth is None:
            depth = self.key_depth
        elif depth == -1:
            depth = None
        for key in await self.keys(
            account_id=account_id,
            depth=depth,
            used=used,
            network=network,
            change=change,
            key_id=key_id,
            is_active=False,
        ):
            addresslist.append(key.address)
        return addresslist

    async def key(self, term) -> WalletKey:
        """
        Return single key with given ID or name as WalletKey object

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> w.key('change 0').address
        '1HabJXe8mTwXiMzUWW5KdpYbFWu3hvtsbF'

        :param term: Search term can be key ID, key address, key WIF or key name
        :type term: int, str

        :return WalletKey: Single key as object
        """

        dbkey = None

        async with self.db.get_session() as session:
            stmt = select(DbKey).filter_by(wallet_id=self.wallet_id)
            if self.purpose:
                stmt = stmt.filter_by(purpose=self.purpose)
            if isinstance(term, numbers.Number):
                res = await session.scalars(stmt.filter_by(id=term))
                dbkey = res.first()
            if not dbkey:
                res = await session.scalars(stmt.filter_by(address=term))
                dbkey = res.first()
            if not dbkey:
                res = await session.scalars(stmt.filter_by(wif=term))
                dbkey = res.first()
            if not dbkey:
                res = await session.scalars(stmt.filter_by(name=term))
                dbkey = res.first()
            if dbkey:
                if dbkey.id in self._key_objects.keys():
                    return self._key_objects[dbkey.id]
                else:
                    wallet_key = await WalletKey.from_db_key(dbkey.id, session)
                    self._key_objects.update({dbkey.id: wallet_key})
                    return wallet_key
            else:
                raise BKeyError("Key '%s' not found" % term)

    def account(self, account_id):
        """
        Returns wallet key of specific BIP44 account.

        Account keys have a BIP44 path depth of 3 and have the format m/purpose'/network'/account'

        I.e: Use account(0).key().wif_public() to get wallet's public master key

        :param account_id: ID of account. Default is 0
        :type account_id: int

        :return WalletKey:
        """

        if "account'" not in self.key_path:
            raise WalletError(
                "Accounts are not supported for this wallet. Account not found in key path %s"
                % self.key_path
            )
        qr = (
            self._session.query(DbKey)
            .filter_by(
                wallet_id=self.wallet_id,
                purpose=self.purpose,
                network_name=self.network.name,
                account_id=account_id,
                depth=3,
            )
            .scalar()
        )
        if not qr:
            raise WalletError(
                "Account with ID %d not found in this wallet" % account_id
            )
        key_id = qr.id
        return self.key(key_id)

    async def accounts(self, network=DEFAULT_NETWORK):
        """
        Get list of accounts for this wallet

        :param network: Network name filter. Default filter is DEFAULT_NETWORK
        :type network: str

        :return list of integers: List of accounts IDs
        """

        if self.multisig and self.cosigner:
            if self.cosigner_id is None:
                raise WalletError(
                    "Missing Cosigner ID value for this wallet, cannot fetch account ID"
                )
            accounts = [
                wk.account_id
                for wk in await self.cosigner[self.cosigner_id].keys_accounts(
                    network=network
                )
            ]
        else:
            accounts = [
                wk.account_id for wk in await self.keys_accounts(network=network)
            ]
        if not accounts:
            accounts = [self.default_account_id]
        return list(dict.fromkeys(accounts))

    async def networks(self, as_dict=False):
        """
        Get list of networks used by this wallet

        :param as_dict: Return as dictionary or as Network objects, default is Network objects
        :type as_dict: bool

        :return list of (Network, dict):
        """

        nw_list = [self.network]
        if self.multisig and self.cosigner:
            keys_qr = (
                self._session.query(DbKey.network_name)
                .filter_by(wallet_id=self.wallet_id, depth=self.key_depth)
                .group_by(DbKey.network_name)
                .all()
            )
            nw_list += [Network(nw[0]) for nw in keys_qr]
        elif self.main_key.key_type != "single":
            wks = await self.keys_networks()
            for wk in wks:
                nw_list.append(Network(wk.network_name))

        networks = []
        nw_list = list(dict.fromkeys(nw_list))
        for nw in nw_list:
            if as_dict:
                nw = nw.__dict__
                if "_sa_instance_state" in nw:
                    del nw["_sa_instance_state"]
            networks.append(nw)

        return networks

    async def network_list(self, field="name"):
        """
        Wrapper for :func:`networks` method, returns a flat list with currently used
        networks for this wallet.

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> w.network_list()
        ['bitcoin']

        :return list of str:
        """

        return [getattr(x, field) for x in await self.networks()]

    async def balance_update_from_serviceprovider(self, account_id=None, network=None):
        """
        Update balance of currents account addresses using default Service objects :func:`getbalance` method. Update total
        wallet balance in database.

        Please Note: Does not update UTXO's or the balance per key! For this use the :func:`updatebalance` method
        instead

        :param account_id: Account ID. Leave empty for default account
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str

        :return int: Total balance
        """

        network, account_id, _ = await self._get_account_defaults(network, account_id)
        balance = Service(
            network=network, providers=self.providers, cache_uri=self.db_cache_uri
        ).getbalance(self.addresslist(account_id=account_id, network=network))
        if balance:
            new_balance = {
                "account_id": account_id,
                "network": network,
                "balance": balance,
            }
            old_balance_item = [
                bi
                for bi in self._balances
                if bi["network"] == network and bi["account_id"] == account_id
            ]
            if old_balance_item:
                item_n = self._balances.index(old_balance_item[0])
                self._balances[item_n] = new_balance
            else:
                self._balances.append(new_balance)
        return balance

    async def balance(self, account_id=None, network=None, as_string=False):
        """
        Get total of unspent outputs

        :param account_id: Account ID filter
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param as_string: Set True to return a string in currency format. Default returns float.
        :type as_string: boolean

        :return float, str: Key balance
        """

        await self._balance_update(account_id, network)
        network, account_id, _ = await self._get_account_defaults(network, account_id)

        balance = 0
        b_res = [
            b["balance"]
            for b in self._balances
            if b["account_id"] == account_id and b["network"] == network
        ]
        if len(b_res):
            balance = b_res[0]
        if as_string:
            return Value.from_satoshi(balance, network=network).str_unit()
        else:
            return float(Value.from_satoshi(balance, network=network))

    async def _balance_update(
        self, account_id=None, network=None, key_id=None, min_confirms=0
    ):
        """
        Update balance from UTXO's in database. To get most recent balance use :func:`utxos_update` first.

        Also updates balance of wallet and keys in this wallet for the specified account or all accounts if
        no account is specified.

        :param account_id: Account ID filter
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param key_id: Key ID Filter
        :type key_id: int
        :param min_confirms: Minimal confirmations needed to include in balance (default = 0)
        :type min_confirms: int

        :return: Updated balance
        """
        async with self.db.get_session() as session:
            stmt = (
                select(
                    DbTransactionOutput.key_id,
                    func.sum(DbTransactionOutput.value),
                    DbTransaction.network_name,
                    DbTransaction.account_id,
                )
                .join_from(DbTransactionOutput, DbTransaction)
                .filter(
                    DbTransactionOutput.spent.is_(False),
                    DbTransaction.wallet_id == self.wallet_id,
                    DbTransaction.confirmations >= min_confirms,
                )
            )
            if account_id is not None:
                stmt = stmt.filter(DbTransaction.account_id == account_id)
            if network is not None:
                stmt = stmt.filter(DbTransaction.network_name == network)
            if key_id is not None:
                stmt = stmt.filter(DbTransactionOutput.key_id == key_id)
            else:
                stmt = stmt.filter(DbTransactionOutput.key_id.isnot(None))
            stmt = stmt.group_by(
                DbTransactionOutput.key_id,
                DbTransactionOutput.transaction_id,
                DbTransactionOutput.output_n,
                DbTransaction.network_name,
                DbTransaction.account_id,
            )
            res = await session.execute(stmt)
            utxos = res.all()

        key_values = [
            {
                "id": utxo[0],
                "network": utxo[2],
                "account_id": utxo[3],
                "balance": utxo[1],
            }
            for utxo in utxos
        ]

        grouper = itemgetter("id", "network", "account_id")
        key_balance_list = []
        for key, grp in groupby(sorted(key_values, key=grouper), grouper):
            nw_acc_dict = dict(zip(["id", "network", "account_id"], key))
            nw_acc_dict["balance"] = sum(item["balance"] for item in grp)
            key_balance_list.append(nw_acc_dict)

        grouper = itemgetter("network", "account_id")
        balance_list = []
        for key, grp in groupby(sorted(key_balance_list, key=grouper), grouper):
            nw_acc_dict = dict(zip(["network", "account_id"], key))
            nw_acc_dict["balance"] = sum(item["balance"] for item in grp)
            balance_list.append(nw_acc_dict)

        # Add keys with no UTXO's with 0 balance
        for key in await self.keys(
            account_id=account_id, network=network, key_id=key_id
        ):
            if key.id not in [utxo[0] for utxo in utxos]:
                key_balance_list.append(
                    {
                        "id": key.id,
                        "network": network,
                        "account_id": key.account_id,
                        "balance": 0,
                    }
                )

        if not key_id:
            for bl in balance_list:
                bl_item = [
                    b
                    for b in self._balances
                    if b["network"] == bl["network"]
                    and b["account_id"] == bl["account_id"]
                ]
                if not bl_item:
                    self._balances.append(bl)
                    continue
                lx = self._balances.index(bl_item[0])
                self._balances[lx].update(bl)

        self._balance = sum(
            [b["balance"] for b in balance_list if b["network"] == self.network.name]
        )

        # Bulk update database
        for kb in key_balance_list:
            if kb["id"] in self._key_objects:
                self._key_objects[kb["id"]]._balance = kb["balance"]

        async with self.db.get_session() as session:
            await session.execute(update(DbKey), key_balance_list)
            await session.commit()

        _logger.info("Got balance for %d key(s)" % len(key_balance_list))
        return self._balances

    async def utxos_update(
        self,
        account_id=None,
        used=None,
        networks=None,
        key_id=None,
        depth=None,
        change=None,
        utxos=None,
        update_balance=True,
        max_utxos=MAX_TRANSACTIONS,
        rescan_all=True,
    ):
        """
        Update UTXO's (Unspent Outputs) for addresses/keys in this wallet using various Service providers.

        This method does not import transactions: use :func:`transactions_update` function or to look for new addresses use :func:`scan`.

        :param account_id: Account ID
        :type account_id: int
        :param used: Only check for UTXO for used or unused keys. Default is both
        :type used: bool
        :param networks: Network name filter as string or list of strings. Leave empty to update all used networks in wallet
        :type networks: str, list
        :param key_id: Key ID to just update 1 key
        :type key_id: int
        :param depth: Only update keys with this depth, default is depth 5 according to BIP0048 standard. Set depth to None to update all keys of this wallet.
        :type depth: int
        :param change: Only update change or normal keys, default is both (None)
        :type change: int
        :param utxos: List of unspent outputs in dictionary format specified below. For usage on an offline PC, you can import utxos with the utxos parameter as a list of dictionaries
        :type utxos: list of dict.

        .. code-block:: json

            {
              "address": "n2S9Czehjvdmpwd2YqekxuUC1Tz5ZdK3YN",
              "script": "",
              "confirmations": 10,
              "output_n": 1,
              "txid": "9df91f89a3eb4259ce04af66ad4caf3c9a297feea5e0b3bc506898b6728c5003",
              "value": 8970937
            }

        :param update_balance: Option to disable balance update after fetching UTXO's. Can be used when utxos_update method is called several times in a row. Default is True
        :type update_balance: bool
        :param max_utxos: Maximum number of UTXO's to update
        :type max_utxos: int
        :param rescan_all: Remove old utxo's and rescan wallet. Default is True. Set to False if you work with large utxo's sets. Value will be ignored if key_id is specified in your call
        :type rescan_all: bool

        :return int: Number of new UTXO's added
        """

        # print("account_id", account_id)
        # print("used", used)
        # print("networks", networks)
        # print("key_id", key_id)
        # print("depth", depth)
        # print("change", change)
        # print("utxos", utxos)
        # print("update_balance", update_balance)
        # print("max_utxos", max_utxos)
        # print("rescan_all", rescan_all)

        _, account_id, _ = await self._get_account_defaults("", account_id, key_id)

        single_key = None
        if key_id:
            single_key = self._session.query(DbKey).filter_by(id=key_id).scalar()
            networks = [single_key.network_name]
            account_id = single_key.account_id
            rescan_all = False

        if networks is None:
            networks = await self.network_list()

        elif not isinstance(networks, list):
            networks = [networks]
        elif len(networks) != 1 and utxos is not None:
            raise WalletError("Please specify maximum 1 network when passing utxo's")

        count_utxos = 0
        for network in networks:
            # Remove current UTXO's
            if rescan_all:
                cur_utxos = (
                    self._session.query(DbTransactionOutput)
                    .join(DbTransaction)
                    .filter(
                        DbTransactionOutput.spent.is_(False),
                        DbTransaction.account_id == account_id,
                        DbTransaction.wallet_id == self.wallet_id,
                        DbTransaction.network_name == network,
                    )
                    .all()
                )
                for u in cur_utxos:
                    self._session.query(DbTransactionOutput).filter_by(
                        transaction_id=u.transaction_id, output_n=u.output_n
                    ).update({DbTransactionOutput.spent: True})
                self._commit()

            if account_id is None and not self.multisig:
                accounts = await self.accounts(network=network)
            else:
                accounts = [account_id]

            for account_id in accounts:
                if depth is None:
                    depth = self.key_depth
                if utxos is None:
                    # Get all UTXO's for this wallet from default Service object
                    addresslist = self.addresslist(
                        account_id=account_id,
                        used=used,
                        network=network,
                        key_id=key_id,
                        change=change,
                        depth=depth,
                    )
                    random.shuffle(addresslist)

                    srv = Service(
                        network=network,
                        providers=self.providers,
                        cache_uri=self.db_cache_uri,
                    )

                    utxos = []
                    for address in addresslist:
                        if rescan_all:
                            last_txid = ""
                        else:
                            last_txid = self.utxo_last(address)
                            # check return type of this
                        new_utxos = await srv.getutxos(
                            address, after_txid=last_txid, limit=max_utxos
                        )

                        if new_utxos:
                            utxos.extend(new_utxos)

                        elif new_utxos is False:
                            raise WalletError(
                                "No response from any service provider, could not update UTXO's. "
                                "Errors: %s" % srv.errors
                            )
                    if srv.complete:
                        self.last_updated = datetime.now()
                    elif utxos and "date" in utxos[-1:][0]:
                        self.last_updated = utxos[-1:][0]["date"]

                # If UTXO is new, add to database otherwise update depth (confirmation count)
                for utxo in utxos:
                    key = single_key

                    if not single_key:
                        key = (
                            self._session.query(DbKey)
                            .filter_by(
                                wallet_id=self.wallet_id, address=utxo["address"]
                            )
                            .scalar()
                        )

                    if not key:
                        raise WalletError(
                            "Key with address %s not found in this wallet"
                            % utxo["address"]
                        )

                    key.used = True
                    status = "unconfirmed"
                    if utxo["confirmations"]:
                        status = "confirmed"

                    # Update confirmations in db if utxo was already imported
                    transaction_in_db = self._session.query(DbTransaction).filter_by(
                        wallet_id=self.wallet_id,
                        txid=bytes.fromhex(utxo["txid"]),
                        network_name=network,
                    )

                    utxo_in_db = (
                        self._session.query(DbTransactionOutput)
                        .join(DbTransaction)
                        .filter(
                            DbTransaction.wallet_id == self.wallet_id,
                            DbTransaction.txid == bytes.fromhex(utxo["txid"]),
                            DbTransactionOutput.output_n == utxo["output_n"],
                        )
                    )

                    spent_in_db = (
                        self._session.query(DbTransactionInput)
                        .join(DbTransaction)
                        .filter(
                            DbTransaction.wallet_id == self.wallet_id,
                            DbTransactionInput.prev_txid == bytes.fromhex(utxo["txid"]),
                            DbTransactionInput.output_n == utxo["output_n"],
                        )
                    )

                    if utxo_in_db.count():
                        utxo_record = utxo_in_db.scalar()

                        if not utxo_record.key_id:
                            count_utxos += 1

                        utxo_record.key_id = key.id
                        utxo_record.spent = bool(spent_in_db.count())

                        if transaction_in_db.count():
                            transaction_record = transaction_in_db.scalar()
                            transaction_record.confirmations = utxo["confirmations"]
                            transaction_record.status = status
                    else:
                        # Add transaction if not exist and then add output
                        if not transaction_in_db.count():
                            block_height = None
                            if block_height in utxo and utxo["block_height"]:
                                block_height = utxo["block_height"]

                            version = 4 if network == "flux" else 1

                            new_tx = DbTransaction(
                                wallet_id=self.wallet_id,
                                txid=bytes.fromhex(utxo["txid"]),
                                version=version,
                                status=status,
                                is_complete=False,
                                block_height=block_height,
                                account_id=account_id,
                                confirmations=utxo["confirmations"],
                                network_name=network,
                            )
                            self._session.add(new_tx)
                            # TODO: Get unique id before inserting to increase performance for large utxo-sets
                            self._commit()
                            tid = new_tx.id
                        else:
                            tid = transaction_in_db.scalar().id

                        script_type = script_type_default(
                            self.witness_type,
                            multisig=self.multisig,
                            locking_script=True,
                        )
                        new_utxo = DbTransactionOutput(
                            transaction_id=tid,
                            output_n=utxo["output_n"],
                            value=utxo["value"],
                            key_id=key.id,
                            address=utxo["address"],
                            script=bytes.fromhex(utxo["script"]),
                            script_type=script_type,
                            spent=bool(spent_in_db.count()),
                        )
                        self._session.add(new_utxo)
                        count_utxos += 1

                    self._commit()

                _logger.info(
                    "Got %d new UTXOs for account %s" % (count_utxos, account_id)
                )
                self._commit()
                if update_balance:
                    await self._balance_update(
                        account_id=account_id,
                        network=network,
                        key_id=key_id,
                        min_confirms=0,
                    )
                utxos = None
        return count_utxos

    async def utxos(self, account_id=None, network=None, min_confirms=0, key_id=None):
        """
        Get UTXO's (Unspent Outputs) from database. Use :func:`utxos_update` method first for updated values

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> w.utxos()  # doctest:+SKIP
        [{'value': 100000000, 'script': '', 'output_n': 0, 'transaction_id': ..., 'spent': False, 'script_type': 'p2pkh', 'key_id': ..., 'address': '16QaHuFkfuebXGcYHmehRXBBX7RG9NbtLg', 'confirmations': 0, 'txid': '748799c9047321cb27a6320a827f1f69d767fe889c14bf11f27549638d566fe4', 'network_name': 'bitcoin'}]

        :param account_id: Account ID
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param min_confirms: Minimal confirmation needed to include in output list
        :type min_confirms: int
        :param key_id: Key ID or list of key IDs to filter utxo's for specific keys
        :type key_id: int, list

        :return list: List of transactions
        """

        first_key_id = key_id
        if isinstance(key_id, list):
            first_key_id = key_id[0]
        network, account_id, _ = await self._get_account_defaults(
            network, account_id, first_key_id
        )

        qr = (
            self._session.query(
                DbTransactionOutput,
                DbKey.address,
                DbTransaction.confirmations,
                DbTransaction.txid,
                DbKey.network_name,
            )
            .join(DbTransaction)
            .join(DbKey)
            .filter(
                DbTransactionOutput.spent.is_(False),
                DbTransaction.account_id == account_id,
                DbTransaction.wallet_id == self.wallet_id,
                DbTransaction.network_name == network,
                DbTransaction.confirmations >= min_confirms,
            )
        )
        if isinstance(key_id, int):
            qr = qr.filter(DbKey.id == key_id)
        elif isinstance(key_id, list):
            qr = qr.filter(DbKey.id.in_(key_id))
        utxos = qr.order_by(DbTransaction.confirmations.desc()).all()
        res = []
        for utxo in utxos:
            u = utxo[0].__dict__
            if "_sa_instance_state" in u:
                del u["_sa_instance_state"]
            u["address"] = utxo[1]
            u["confirmations"] = int(utxo[2])
            u["txid"] = utxo[3].hex()
            u["network_name"] = utxo[4]
            res.append(u)
        return res

    def utxo_add(self, address, value, txid, output_n, confirmations=1, script=""):
        """
        Add a single UTXO to the wallet database. To update all utxo's use :func:`utxos_update` method.

        Use this method for testing, offline wallets or if you wish to override standard method of retreiving UTXO's

        This method does not check if UTXO exists or is still spendable.

        :param address: Address of Unspent Output. Address should be available in wallet
        :type address: str
        :param value: Value of output in sathosis or smallest denominator for type of currency
        :type value: int
        :param txid: Transaction hash or previous output as hex-string
        :type txid: str
        :param output_n: Output number of previous transaction output
        :type output_n: int
        :param confirmations: Number of confirmations. Default is 0, unconfirmed
        :type confirmations: int
        :param script: Locking script of previous output as hex-string
        :type script: str

        :return int: Number of new UTXO's added, so 1 if successful
        """

        utxo = {
            "address": address,
            "script": script,
            "confirmations": confirmations,
            "output_n": output_n,
            "txid": txid,
            "value": value,
        }
        return self.utxos_update(utxos=[utxo])

    def utxo_last(self, address):
        """
        Get transaction ID for latest utxo in database for given address

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> w.utxo_last('16QaHuFkfuebXGcYHmehRXBBX7RG9NbtLg')
        '748799c9047321cb27a6320a827f1f69d767fe889c14bf11f27549638d566fe4'

        :param address: The address
        :type address: str

        :return str:
        """
        to = (
            self._session.query(DbTransaction.txid, DbTransaction.confirmations)
            .join(DbTransactionOutput)
            .join(DbKey)
            .filter(
                DbKey.address == address,
                DbTransaction.wallet_id == self.wallet_id,
                DbTransactionOutput.spent.is_(False),
            )
            .order_by(DbTransaction.confirmations)
            .first()
        )
        return "" if not to else to[0].hex()

    async def transactions_update_confirmations(self):
        """
        Update number of confirmations and status for transactions in database

        :return:
        """
        network = self.network.name

        srv = Service(
            network=network,
            providers=self.providers,
            cache_uri=self.db_cache_uri,
        )
        blockcount = await srv.blockcount()
        async with self.db.get_session() as session:
            res = await session.scalars(
                select(DbTransaction).filter(
                    DbTransaction.wallet_id == self.wallet_id,
                    DbTransaction.network_name == network,
                    DbTransaction.block_height > 0,
                )
            )
            db_txs = res.all()

            # do these concurrently
            for db_tx in db_txs:
                db_tx.confirmations = blockcount - db_tx.block_height
                # await session.execute(
                #     update(DbTransaction)
                #     .filter_by(id=db_tx.id)
                #     .values(
                #         {
                #             DbTransaction.status: "confirmed",
                #             DbTransaction.confirmations: (
                #                 blockcount - DbTransaction.block_height
                #             )
                #             + 1,
                #         }
                #     )
                # )
            await session.commit()

    async def transactions_update_by_txids(self, txids: list[bytes] | bytes):
        """
        Update transaction or list or transaction for this wallet with provided transaction ID

        :param txids: Transaction ID, or list of transaction IDs
        :type txids: str, list of str, bytes, list of bytes

        :return:
        """
        if not isinstance(txids, list):
            txids = [txids]
        # txids = list(dict.fromkeys(txids))

        srv = Service(
            network=self.network.name,
            providers=self.providers,
            cache_uri=self.db_cache_uri,
        )
        txids_hexstrings = [to_hexstring(x) for x in txids]
        txs = await srv.get_transactions(txids_hexstrings)

        # TODO: Avoid duplicate code in this method and transaction_update()
        utxo_set = set()
        for t in txs:
            wt = await WalletTransaction.create(self, t)
            await wt.store()

            utxos = [(ti.prev_txid.hex(), ti.output_n_int) for ti in wt.tx.inputs]
            utxo_set.update(utxos)

        async with self.db.get_session() as session:
            for utxo in list(utxo_set):
                res = await session.scalars(
                    select(DbTransactionOutput)
                    .join(DbTransaction)
                    .filter(
                        DbTransaction.txid == bytes.fromhex(utxo[0]),
                        DbTransactionOutput.output_n == utxo[1],
                        DbTransactionOutput.spent.is_(False),
                    )
                )
                tos = res.all()

                for u in tos:
                    u.spent = True

            await session.commit()

        # self._balance_update(account_id=account_id, network=network, key_id=key_id)

    async def create_and_store_wallet_tx(
        self, tx: GenericTransaction, addresslist: list[str]
    ) -> set[tuple[str, int]]:
        wt = WalletTransaction(self, tx, addresslist=addresslist)
        await wt.store()
        # return the wt and ground them pass in the session to store
        # await wt.store()

        utxos = {(ti.prev_txid.hex(), ti.output_n_int) for ti in wt.tx.inputs}
        return utxos

    # testing
    async def store_transactions(self, txs: list[WalletTransaction]) -> set:
        utxo_set = set()

        async with self.db.get_session() as session:
            for wt in txs:
                # hack
                version = 4 if wt.tx.network.name == "flux" else 1

                # figure it's better to try store than to select. As another
                # task might be just about to flush the session. This method
                # gets called from each scan_key. Txs an go between keys etc

                new_tx = DbTransaction(
                    wallet_id=self.wallet_id,
                    version=version,
                    txid=bytes.fromhex(wt.tx.txid),
                    block_height=wt.tx.block_height,
                    size=wt.tx.size,
                    confirmations=wt.tx.confirmations,
                    date=wt.tx.date,
                    fee=wt.tx.fee,
                    status=wt.status,
                    input_total=wt.tx.input_total,
                    output_total=wt.tx.output_total,
                    network_name=wt.tx.network.name,
                    raw=wt.tx.rawtx,
                    verified=wt.tx.verified,
                    account_id=wt.account_id,
                    coinbase=wt.tx.coinbase,
                    expiry_height=wt.tx.expiry_height,
                )

                session.add(new_tx)

                try:
                    await session.flush()
                except IntegrityError:
                    await session.rollback()
                    continue

                txidn = new_tx.id

                for ti in wt.tx.inputs:
                    res = await session.scalars(
                        select(DbKey).filter_by(
                            wallet_id=self.wallet_id, address=ti.address
                        )
                    )
                    tx_key = res.first()

                    key_id = None
                    if tx_key:
                        key_id = tx_key.id
                        tx_key.used = True

                    witnesses = int_to_varbyteint(len(ti.witnesses)) + b"".join(
                        [bytes(varstr(w)) for w in ti.witnesses]
                    )

                    new_tx_inp = DbTransactionInput(
                        transaction_id=txidn,
                        output_n=ti.output_n_int,
                        key_id=key_id,
                        value=ti.value,
                        prev_txid=ti.prev_txid,
                        index_n=ti.index_n,
                        double_spend=ti.double_spend,
                        script=ti.unlocking_script,
                        script_type=ti.script_type,
                        witness_type=ti.witness_type,
                        sequence=ti.sequence,
                        address=ti.address,
                        witnesses=witnesses,
                    )
                    session.add(new_tx_inp)

                for to in wt.tx.outputs:
                    res = await session.scalars(
                        select(DbKey).filter_by(
                            wallet_id=self.wallet_id, address=to.address
                        )
                    )
                    tx_key = res.first()
                    key_id = None

                    if tx_key:
                        key_id = tx_key.id
                        tx_key.used = True

                    spent = to.spent

                    new_tx_out = DbTransactionOutput(
                        transaction_id=txidn,
                        output_n=to.output_n,
                        key_id=key_id,
                        address=to.address,
                        value=to.value,
                        spent=spent,
                        script=to.lock_script,
                        script_type=to.script_type,
                    )
                    session.add(new_tx_out)

                for ti in wt.tx.inputs:
                    utxo_set.add((ti.prev_txid.hex(), ti.output_n_int))
                await session.flush()
            await session.commit()
        return utxo_set

    async def transactions_update(
        self,
        account_id: int | None = None,
        used: bool | None = None,
        network: str | None = None,
        key_id: int | None = None,
        depth: int | None = None,
        change: int | None = None,
        limit: int = MAX_TRANSACTIONS,
        update_confirmations: bool = True,
    ) -> set[str]:
        """
        Update wallets transaction from service providers. Get all transactions for known keys in this wallet. The balances and unspent outputs (UTXO's) are updated as well. Only scan keys from default network and account unless another network or account is specified.

        Use the :func:`scan` method for automatic address generation/management, and use the :func:`utxos_update` method to only look for unspent outputs and balances.

        :param account_id: Account ID
        :type account_id: int
        :param used: Only update used or unused keys, specify None to update both. Default is None
        :type used: bool, None
        :param network: Network name. Leave empty for default network
        :type network: str
        :param key_id: Key ID to just update 1 key
        :type key_id: int
        :param depth: Only update keys with this depth, default is depth 5 according to BIP0048 standard. Set depth to None to update all keys of this wallet.
        :type depth: int
        :param change: Only update change or normal keys, default is both (None)
        :type change: int
        :param limit: Stop update after limit transactions to avoid timeouts with service providers. Default is MAX_TRANSACTIONS defined in config.py
        :type limit: int

        :return int: Number of transactions that were discovered.
        """

        # print("TRANSACTIONS UPDATE")
        # print("ACCOUNT ID", account_id)
        # print("USED", used)
        # print("ETNWORK", network)
        # print("HEY ID", key_id)
        # print("DEPTH", depth)
        # print("CHANGE", change)
        # print("LIMIT", limit)
        # print("UPDATE CONF", update_confirmations)

        network, account_id, _ = await self._get_account_defaults(
            network, account_id, key_id
        )

        if depth is None:
            depth = self.key_depth
        # Update number of confirmations and status for already known transactions

        if update_confirmations:
            await self.transactions_update_confirmations()

        srv = Service(
            network=network,
            providers=self.providers,
            cache_uri=self.db_cache_uri,
        )

        addresslist = await self.addresslist(
            account_id=account_id,
            used=used,
            network=network,
            key_id=key_id,
            change=change,
            depth=depth,
        )

        self.last_updated = datetime.now()

        new_txids = set()

        for address in addresslist:
            tx_count = 0

            last_tx_index = await self.transaction_last(address, by_index=True)
            tx_generator = srv.get_transactions_by_address(
                address,
                limit=limit,
                after_tx_index=last_tx_index,
            )

            utxo_set = set()

            async for txs in tx_generator:
                tx_count += len(txs)

                wallet_txs = []
                for tx in txs:
                    # tx's can be between keys in the same wallet (or same key)
                    # do our best to filter these out
                    if not tx.txid in new_txids:
                        wallet_txs.append(
                            WalletTransaction(self, tx, addresslist=addresslist)
                        )
                        new_txids.add(tx.txid)

                utxos = await self.store_transactions(wallet_txs)
                utxo_set.update(utxos)

            async with self.db.get_session() as session:
                for utxo in utxo_set:
                    res = await session.scalars(
                        select(DbTransactionOutput)
                        .join(DbTransaction)
                        .filter(
                            DbTransaction.txid == bytes.fromhex(utxo[0]),
                            DbTransactionOutput.output_n == utxo[1],
                            DbTransactionOutput.spent.is_(False),
                            DbTransaction.wallet_id == self.wallet_id,
                        )
                    )
                    tos = res.all()

                    for u in tos:
                        u.spent = True

                # if last_txid:
                #     res = await session.execute(
                #         update(DbKey)
                #         .where(
                #             DbKey.address == address,
                #             DbKey.wallet_id == self.wallet_id,
                #         )
                #         .values({DbKey.latest_txid: bytes.fromhex(last_txid)})
                #     )
                if tx_count:
                    res = await session.execute(
                        update(DbKey)
                        .where(
                            DbKey.address == address,
                            DbKey.wallet_id == self.wallet_id,
                        )
                        .values({DbKey.latest_tx_index: tx_count + last_tx_index})
                    )

                await session.commit()

        await self._balance_update(
            account_id=account_id, network=network, key_id=key_id
        )

        return new_txids

    async def transaction_last(self, address: str, by_index: bool = False) -> str | int:
        """
        Get transaction ID for latest transaction in database for given address

        :param address: The address
        :type address: str

        :return str:
        """

        # this is stupid, fix

        async with self.db.get_session() as session:
            if by_index:
                res = await session.scalars(
                    select(DbKey.latest_tx_index).filter(
                        DbKey.address == address, DbKey.wallet_id == self.wallet_id
                    )
                )
                last_tx_index: int = res.first()
                last_index = 0 if last_tx_index is None else last_tx_index
            else:
                res = await session.scalars(
                    select(DbKey.latest_txid).filter(
                        DbKey.address == address, DbKey.wallet_id == self.wallet_id
                    )
                )
                txid: bytes = res.first()
                last_tx = "" if not txid else txid.hex()

        return last_index if by_index else last_tx

    async def transactions(
        self,
        account_id: int | None = None,
        network: str | None = None,
        include_new: bool = False,
        key_id: int | None = None,
        as_dict: bool = False,
    ) -> list[WalletTransaction] | list[dict]:
        """
        Get all known transactions input and outputs for this wallet.

        The transaction only includes the inputs and outputs related to this wallet. To get full transactions
        use the :func:`transactions_full` method.

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> w.transactions()
        [<WalletTransaction(input_count=0, output_count=1, status=confirmed, network=bitcoin)>]

        :param account_id: Filter by Account ID. Leave empty for default account_id
        :type account_id: int, None
        :param network: Filter by network name. Leave empty for default network
        :type network: str, None
        :param include_new: Also include new and incomplete transactions in list. Default is False
        :type include_new: bool
        :param key_id: Filter by key ID
        :type key_id: int, None
        :param as_dict: Output as dictionary or WalletTransaction object
        :type as_dict: bool

        :return list of WalletTransaction: List of WalletTransaction or transactions as dictionary
        """

        network, account_id, _ = await self._get_account_defaults(
            network, account_id, key_id
        )

        async with self.db.get_session() as session:
            # Transaction inputs
            stmt = (
                select(
                    DbTransactionInput,
                    DbTransactionInput.address,
                    DbTransaction.confirmations,
                    DbTransaction.txid,
                    DbTransaction.network_name,
                    DbTransaction.status,
                )
                .join(DbTransaction)
                .join(DbKey)
                .filter(
                    DbTransaction.account_id == account_id,
                    DbTransaction.wallet_id == self.wallet_id,
                    DbKey.wallet_id == self.wallet_id,
                    DbTransaction.network_name == network,
                )
            )
            if key_id is not None:
                stmt = stmt.filter(DbTransactionInput.key_id == key_id)
            if not include_new:
                stmt = stmt.filter(
                    or_(
                        DbTransaction.status == "confirmed",
                        DbTransaction.status == "unconfirmed",
                    )
                )
            res = await session.execute(stmt)
            txs = res.all()

            # Transaction outputs
            stmt = (
                select(
                    DbTransactionOutput,
                    DbTransactionOutput.address,
                    DbTransaction.confirmations,
                    DbTransaction.txid,
                    DbTransaction.network_name,
                    DbTransaction.status,
                )
                .join(DbTransaction)
                .join(DbKey)
                .filter(
                    DbTransaction.account_id == account_id,
                    DbTransaction.wallet_id == self.wallet_id,
                    DbKey.wallet_id == self.wallet_id,
                    DbTransaction.network_name == network,
                )
            )
            if key_id is not None:
                stmt = stmt.filter(DbTransactionOutput.key_id == key_id)
            if not include_new:
                stmt = stmt.filter(
                    or_(
                        DbTransaction.status == "confirmed",
                        DbTransaction.status == "unconfirmed",
                    )
                )

            res = await session.execute(stmt)
            txs.extend(res.all())

            # fix this
            for tx in txs:
                await tx[0].awaitable_attrs.transaction

            txs = sorted(
                txs,
                key=lambda k: (k[2], pow(10, 20) - k[0].transaction_id, k[3]),
                reverse=True,
            )

        res = []
        txids = []
        for tx in txs:
            txid = tx[3].hex()
            if as_dict:
                u = tx[0].__dict__
                u["block_height"] = tx[0].transaction.block_height
                u["date"] = tx[0].transaction.date
                if "_sa_instance_state" in u:
                    del u["_sa_instance_state"]
                u["address"] = tx[1]
                u["confirmations"] = None if tx[2] is None else int(tx[2])
                u["txid"] = txid
                u["network_name"] = tx[4]
                u["status"] = tx[5]
                if "index_n" in u:
                    u["is_output"] = True
                    u["value"] = -u["value"]
                else:
                    u["is_output"] = False
            else:
                if txid in txids:
                    continue
                txids.append(txid)
                u = self.transaction(txid)
            res.append(u)

        return res

    async def transactions_full(
        self,
        network: str | None = None,
        include_new: bool = False,
        limit: int = 0,
        offset: int = 0,
    ) -> Iterator[list[WalletTransaction]]:
        """
        Get all transactions of this wallet as WalletTransaction objects

        Use the :func:`transactions` method to only get the inputs and outputs transaction parts related to this wallet

        :param network: Filter by network name. Leave empty for default network
        :type network: str
        :param include_new: Also include new and incomplete transactions in list. Default is False
        :type include_new: bool
        :param limit: Maximum number of transactions to return. Combine with offset parameter to use as pagination
        :type limit: int
        :param offset: Number of transactions to skip
        :type offset: int

        :return list of WalletTransaction:
        """
        network, _, _ = await self._get_account_defaults(network)
        addresslist = await self.addresslist()

        async with self.db.get_session() as session:
            stmt = select(
                DbTransaction.txid, DbTransaction.network_name, DbTransaction.status
            ).filter(
                DbTransaction.wallet_id == self.wallet_id,
                DbTransaction.network_name == network,
            )
            if not include_new:
                stmt = stmt.filter(
                    or_(
                        DbTransaction.status == "confirmed",
                        DbTransaction.status == "unconfirmed",
                    )
                )
            # changed this from block_height to date. As unconfirmed don't have block height
            stmt = stmt.order_by(DbTransaction.date.desc())

            # txs: list[WalletTransaction] = []
            if limit:
                stmt = stmt.limit(limit)
            if offset:
                stmt = stmt.offset(offset)

            res = await session.execute(stmt)
            found_txs = res.all()

        # txs = []

        total = len(found_txs)
        complete = 0
        step = 20
        while complete <= total:
            # txs = []
            tasks = []
            end = complete + step
            for tx in found_txs[complete:end]:
                tasks.append(self.transaction(tx.txid.hex(), addresslist))
                # txs.append(await self.transaction(tx.txid.hex(), addresslist))

            complete += step
            txs = await asyncio.gather(*tasks)

            if txs:
                yield txs

    async def transactions_export(
        self,
        account_id: int | None = None,
        network: str | None = None,
        include_new: bool = False,
        key_id: int | None = None,
        skip_change: bool = True,
    ):
        """
        Export wallets transactions as list of tuples with the following fields:
            (transaction_date, transaction_hash, in/out, addresses_in, addresses_out, value, value_cumulative, fee)

        :param account_id: Filter by Account ID. Leave empty for default account_id
        :type account_id: int, None
        :param network: Filter by network name. Leave empty for default network
        :type network: str, None
        :param include_new: Also include new and incomplete transactions in list. Default is False
        :type include_new: bool
        :param key_id: Filter by key ID
        :type key_id: int, None
        :param skip_change: Do not include change outputs. Default is True
        :type skip_change: bool

        :return list of tuple:
        """

        txs_tuples = []
        cumulative_value = 0
        for t in await self.transactions(account_id, network, include_new, key_id):
            te = t.export(skip_change=skip_change)

            # When transaction is outgoing deduct fee from cumulative value
            if t.outgoing_tx:
                cumulative_value -= t.tx.fee

            # Loop through all transaction inputs and outputs
            for tei in te:
                # Create string with  list of inputs addresses for incoming transactions, and outputs addresses
                # for outgoing txs
                addr_list_in = tei[3] if isinstance(tei[3], list) else [tei[3]]
                addr_list_out = tei[4] if isinstance(tei[4], list) else [tei[4]]
                cumulative_value += tei[5]
                txs_tuples.append(
                    (
                        tei[0],
                        tei[1],
                        tei[2],
                        addr_list_in,
                        addr_list_out,
                        tei[5],
                        cumulative_value,
                        tei[6],
                    )
                )
        return txs_tuples

    async def transaction(
        self, txid: str, addresslist: list[str] | None = None
    ) -> WalletTransaction:
        """
        Get WalletTransaction object for given transaction ID (transaction hash)

        :param txid: Hexadecimal transaction hash
        :type txid: str

        :return WalletTransaction:
        """
        return await WalletTransaction.from_txid(self, txid, addresslist)

    async def transaction_spent(self, txid: str, output_n: int | bytes):
        """
        Check if transaction with given transaction ID and output_n is spent and return txid of spent transaction.

        Retrieves information from database, does not update transaction and does not check if transaction is spent with service providers.

        :param txid: Hexadecimal transaction hash
        :type txid: str, bytes
        :param output_n: Output n
        :type output_n: int, bytes

        :return str: Transaction ID
        """
        txid = to_bytes(txid)

        if isinstance(output_n, bytes):
            output_n = int.from_bytes(output_n, "big")

        async with self.db.get_session() as session:
            res = await session.scalars(
                select(
                    DbTransactionInput,
                    DbTransaction.confirmations,
                    DbTransaction.txid,
                    DbTransaction.status,
                )
                .join(DbTransaction)
                .filter(
                    DbTransaction.wallet_id == self.wallet_id,
                    DbTransactionInput.prev_txid == txid,
                    DbTransactionInput.output_n == output_n,
                )
            )
            input: DbTransactionInput = res.first()

            if input:
                await input.awaitable_attrs.transaction
                return input.transaction.txid.hex()

    async def _objects_by_key_id(self, key_id: int) -> tuple[list[HDKey], DbKey]:
        async with self.db.get_session() as session:
            key = await session.get(DbKey, key_id)

        if not key:
            raise WalletError("Key '%s' not found in this wallet" % key_id)
        if key.key_type == "multisig":
            inp_keys = [
                HDKey.from_wif(ck.child_key.wif, network=ck.child_key.network_name)
                for ck in key.multisig_children
            ]
        elif key.key_type in ["bip32", "single"]:
            if not key.wif:
                raise WalletError("WIF of key is empty cannot create HDKey")
            inp_keys = [HDKey.from_wif(key.wif, network=key.network_name)]
        else:
            raise WalletError("Input key type %s not supported" % key.key_type)
        return inp_keys, key

    async def select_inputs(
        self,
        amount,
        variance=None,
        input_key_id=None,
        account_id=None,
        network=None,
        min_confirms=1,
        max_utxos=None,
        return_input_obj=True,
        skip_dust_amounts=True,
    ):
        """
        Select available unspent transaction outputs (UTXO's) which can be used as inputs for a transaction for
        the specified amount.

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> w.select_inputs(50000000)
        [<Input(prev_txid='748799c9047321cb27a6320a827f1f69d767fe889c14bf11f27549638d566fe4', output_n=0, address='16QaHuFkfuebXGcYHmehRXBBX7RG9NbtLg', index_n=0, type='sig_pubkey')>]

        :param amount: Total value of inputs in the smallest denominator (sathosi) to select
        :type amount: int
        :param variance: Allowed difference in total input value. Default is dust amount of selected network. Difference will be added to transaction fee.
        :type variance: int
        :param input_key_id: Limit UTXO's search for inputs to this key ID or list of key IDs. Only valid if no input array is specified
        :type input_key_id: int, list
        :param account_id: Account ID
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param min_confirms: Minimal confirmation needed for an UTXO before it will be included in inputs. Default is 1 confirmation. Option is ignored if input_arr is provided.
        :type min_confirms: int
        :param max_utxos: Maximum number of UTXO's to use. Set to 1 for optimal privacy. Default is None: No maximum
        :type max_utxos: int
        :param return_input_obj: Return inputs as Input class object. Default is True
        :type return_input_obj: bool
        :param skip_dust_amounts: Do not include small amount to avoid dust inputs
        :type skip_dust_amounts: bool

        :return: List of previous outputs
        :rtype: list of DbTransactionOutput, list of Input
        """

        network, account_id, _ = await self._get_account_defaults(network, account_id)
        dust_amount = Network(network).dust_amount

        if variance is None:
            variance = dust_amount

        async with self.db.get_session() as session:
            stmt = (
                select(DbTransactionOutput)
                .join(DbTransaction)
                .join(DbKey)
                .filter(
                    DbTransaction.wallet_id == self.wallet_id,
                    DbTransaction.account_id == account_id,
                    DbTransaction.network_name == network,
                    DbKey.public != b"",
                    DbTransactionOutput.spent.is_(False),
                    DbTransaction.confirmations >= min_confirms,
                )
            )

            if input_key_id:
                if isinstance(input_key_id, int):
                    stmt = stmt.filter(DbKey.id == input_key_id)
                else:
                    stmt = stmt.filter(DbKey.id.in_(input_key_id))

            if skip_dust_amounts:
                stmt = stmt.filter(DbTransactionOutput.value > dust_amount)

            stmt = stmt.order_by(DbTransaction.confirmations.desc())

            res = await session.scalars(stmt)
            utxos = res.all()

            if not utxos:
                raise WalletError(
                    "Create transaction: No unspent transaction outputs found or no key available for UTXO's"
                )

            # TODO: Find 1 or 2 UTXO's with exact amount +/- self.network.dust_amount

            # Try to find one utxo with exact amount
            res = await session.scalars(
                stmt.filter(
                    DbTransactionOutput.spent.is_(False),
                    DbTransactionOutput.value >= amount,
                    DbTransactionOutput.value <= amount + variance,
                )
            )

            one_utxo = res.first()

            selected_utxos = []
            if one_utxo:
                selected_utxos = [one_utxo]
            else:
                # Try to find one utxo with higher amount
                res = await session.scalars(
                    stmt.filter(
                        DbTransactionOutput.spent.is_(False),
                        DbTransactionOutput.value >= amount,
                    ).order_by(DbTransactionOutput.value)
                )

                one_utxo = res.first()

                if one_utxo:
                    selected_utxos = [one_utxo]

                elif max_utxos and max_utxos <= 1:
                    _logger.info(
                        "No single UTXO found with requested amount, use higher 'max_utxo' setting to use "
                        "multiple UTXO's"
                    )
                    return []

            # Otherwise compose of 2 or more lesser outputs
            if not selected_utxos:
                res = await session.scalars(
                    stmt.filter(
                        DbTransactionOutput.spent.is_(False),
                        DbTransactionOutput.value < amount,
                    ).order_by(DbTransactionOutput.value.desc())
                )

                lessers = res.all()

                total_amount = 0
                selected_utxos = []
                for utxo in lessers[:max_utxos]:
                    if total_amount < amount:
                        selected_utxos.append(utxo)
                        total_amount += utxo.value
                if total_amount < amount:
                    return []

            # fix this
            for utxo in selected_utxos:
                await utxo.awaitable_attrs.transaction
                await utxo.awaitable_attrs.key

        if not return_input_obj:
            return selected_utxos
        else:
            inputs = []
            for utxo in selected_utxos:
                # amount_total_input += utxo.value
                inp_keys, key = await self._objects_by_key_id(utxo.key_id)
                multisig = False if len(inp_keys) < 2 else True
                script_type = get_unlocking_script_type(
                    utxo.script_type, multisig=multisig
                )
                inputs.append(
                    Input(
                        utxo.transaction.txid,
                        utxo.output_n,
                        keys=inp_keys,
                        script_type=script_type,
                        sigs_required=self.multisig_n_required,
                        sort=self.sort_keys,
                        address=key.address,
                        compressed=key.compressed,
                        value=utxo.value,
                        network=key.network_name,
                    )
                )
            return inputs

    async def transaction_create(
        self,
        output_arr: list[Output] | tuple,
        input_arr: list[Input] | None = None,
        input_key_id: int | None = None,
        account_id: int | None = None,
        network: str | None = None,
        fee: int | str | None = None,
        min_confirms: int = 1,
        max_utxos: int | None = None,
        locktime: int = 0,
        number_of_change_outputs: int = 1,
        random_output_order: bool = True,
        message: str = "",
    ) -> WalletTransaction:
        """
        Create new transaction with specified outputs.

        Inputs can be specified but if not provided they will be selected from wallets utxo's with :func:`select_inputs` method.

        Output array is a list of 1 or more addresses and amounts.

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> t = w.transaction_create([('1J9GDZMKEr3ZTj8q6pwtMy4Arvt92FDBTb', 200000)])
        >>> t
        <WalletTransaction(input_count=1, output_count=2, status=new, network=bitcoin)>
        >>> t.outputs # doctest:+ELLIPSIS
        [<Output(value=..., address=..., type=p2pkh)>, <Output(value=..., address=..., type=p2pkh)>]

        :param output_arr: List of output as Output objects or tuples with address and amount. Must contain at least one item. Example: [('mxdLD8SAGS9fe2EeCXALDHcdTTbppMHp8N', 5000000)]
        :type output_arr: list of Output, tuple
        :param input_arr: List of inputs as Input objects or tuples with reference to a UTXO, a wallet key and value. The format is [(txid, output_n, key_ids, value, signatures, unlocking_script, address)]
        :type input_arr: list of Input, tuple
        :param input_key_id: Limit UTXO's search for inputs to this key_id. Only valid if no input array is specified
        :type input_key_id: int
        :param account_id: Account ID
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param fee: Set fee manually, leave empty to calculate fees automatically. Set fees in the smallest currency  denominator, for example satoshi's if you are using bitcoins. You can also supply a string: 'low', 'normal' or 'high' to determine fees automatically.
        :type fee: int, str
        :param min_confirms: Minimal confirmation needed for an UTXO before it will be included in inputs. Default is 1 confirmation. Option is ignored if input_arr is provided.
        :type min_confirms: int
        :param max_utxos: Maximum number of UTXO's to use. Set to 1 for optimal privacy. Default is None: No maximum
        :type max_utxos: int
        :param locktime: Transaction level locktime. Locks the transaction until a specified block (value from 1 to 5 million) or until a certain time (Timestamp in seconds after 1-jan-1970). Default value is 0 for transactions without locktime
        :type locktime: int
        :param number_of_change_outputs: Number of change outputs to create when there is a change value. Default is 1. Use 0 for random number of outputs: between 1 and 5 depending on send and change amount        :type number_of_change_outputs: int
        :type number_of_change_outputs: int
        :param random_output_order: Shuffle order of transaction outputs to increase privacy. Default is True
        :type random_output_order: bool

        :return WalletTransaction: object
        """

        if not isinstance(output_arr, list):
            raise WalletError(
                "Output array must be a list of tuples with address and amount. "
                "Use 'send_to' method to send to one address"
            )
        if not network and output_arr:
            if isinstance(output_arr[0], Output):
                network = output_arr[0].network.name
            elif isinstance(output_arr[0][1], str):
                network = Value(output_arr[0][1]).network.name
        network, account_id, _ = await self._get_account_defaults(network, account_id)

        if input_arr and max_utxos and len(input_arr) > max_utxos:
            raise WalletError(
                "Input array contains %d UTXO's but max_utxos=%d parameter specified"
                % (len(input_arr), max_utxos)
            )

        srv = Service(
            network=network,
            providers=self.providers,
            cache_uri=self.db_cache_uri,
        )
        # ToDo: maybe make this configurable?
        expiry_height = await srv.blockcount() + 21

        # Create transaction and add outputs
        amount_total_output = 0

        match network:
            case "flux":
                Klass = FluxTransaction
            case _:
                Klass = BitcoinTransaction

        tx = Klass(
            network=network,
            locktime=locktime,
            expiry_height=expiry_height,
        )

        for o in output_arr:
            if isinstance(o, Output):
                tx.outputs.append(o)
                amount_total_output += o.value
            else:
                value = value_to_satoshi(o[1], network=tx.network)
                amount_total_output += value
                addr = o[0]
                if isinstance(addr, WalletKey):
                    addr = addr.key()
                tx.add_output(value, addr)

        tx.fee_per_kb = None
        if isinstance(fee, int):
            fee_estimate = fee
        else:
            n_blocks = 3
            priority = ""
            if isinstance(fee, str):
                priority = fee
            tx.fee_per_kb = await srv.estimatefee(blocks=n_blocks, priority=priority)
            if not input_arr:
                fee_estimate = int(
                    tx.estimate_size(number_of_change_outputs=number_of_change_outputs)
                    / 1000.0
                    * tx.fee_per_kb
                )
            else:
                fee_estimate = 0
            if isinstance(fee, str):
                fee = fee_estimate

        # Add inputs
        sequence = 0xFFFFFFFF
        if 0 < tx.locktime < 0xFFFFFFFF:
            sequence = 0xFFFFFFFE
        amount_total_input = 0

        if input_arr is None:
            selected_utxos = await self.select_inputs(
                amount_total_output + fee_estimate,
                tx.network.dust_amount,
                input_key_id,
                account_id,
                network,
                min_confirms,
                max_utxos,
                False,
            )

            if not selected_utxos:
                raise WalletError("Not enough unspent transaction outputs found")

            for utxo in selected_utxos:
                amount_total_input += utxo.value
                inp_keys, key = await self._objects_by_key_id(utxo.key_id)
                multisig = (
                    False if isinstance(inp_keys, list) and len(inp_keys) < 2 else True
                )

                unlock_script_type = get_unlocking_script_type(
                    utxo.script_type, self.witness_type, multisig=multisig
                )

                tx.add_input(
                    utxo.transaction.txid,
                    utxo.output_n,
                    keys=inp_keys,
                    script_type=unlock_script_type,
                    sigs_required=self.multisig_n_required,
                    sort=self.sort_keys,
                    compressed=key.compressed,
                    value=utxo.value,
                    address=utxo.key.address,
                    sequence=sequence,
                    key_path=utxo.key.path,
                    witness_type=self.witness_type,
                )
                # FIXME: Missing locktime_cltv=locktime_cltv, locktime_csv=locktime_csv (?)
        else:
            for inp in input_arr:
                locktime_cltv = None
                locktime_csv = None
                unlocking_script_unsigned = None
                unlocking_script_type = ""
                if isinstance(inp, Input):
                    prev_txid = inp.prev_txid
                    output_n = inp.output_n
                    key_id = None
                    value = inp.value
                    signatures = inp.signatures
                    unlocking_script = inp.unlocking_script
                    unlocking_script_unsigned = inp.unlocking_script_unsigned
                    unlocking_script_type = inp.script_type
                    address = inp.address
                    sequence = inp.sequence
                    locktime_cltv = inp.locktime_cltv
                    locktime_csv = inp.locktime_csv
                # elif isinstance(inp, DbTransactionOutput):
                #     prev_txid = inp.transaction.txid
                #     output_n = inp.output_n
                #     key_id = inp.key_id
                #     value = inp.value
                #     signatures = None
                #     # FIXME: This is probably not an unlocking_script
                #     unlocking_script = inp.script
                #     unlocking_script_type = get_unlocking_script_type(inp.script_type)
                #     address = inp.key.address
                else:
                    prev_txid = inp[0]
                    output_n = inp[1]
                    key_id = None if len(inp) <= 2 else inp[2]
                    value = 0 if len(inp) <= 3 else inp[3]
                    signatures = None if len(inp) <= 4 else inp[4]
                    unlocking_script = b"" if len(inp) <= 5 else inp[5]
                    address = "" if len(inp) <= 6 else inp[6]
                # Get key_ids, value from Db if not specified
                if not (key_id and value and unlocking_script_type):
                    if not isinstance(output_n, TYPE_INT):
                        output_n = int.from_bytes(output_n, "big")

                    async with self.db.get_session() as session:
                        res = (
                            await session.scalars(DbTransactionOutput)
                            .join(DbTransaction)
                            .filter(
                                DbTransaction.wallet_id == self.wallet_id,
                                DbTransaction.txid == to_bytes(prev_txid),
                                DbTransactionOutput.output_n == output_n,
                            )
                        )

                        inp_utxo: DbTransactionOutput | None = res.first()

                        if inp_utxo:
                            await inp_utxo.awaitable_attrs.key

                            key_id = inp_utxo.key_id
                            value = inp_utxo.value
                            address = inp_utxo.key.address
                            unlocking_script_type = get_unlocking_script_type(
                                inp_utxo.script_type, multisig=self.multisig
                            )
                            # witness_type = inp_utxo.witness_type
                        else:
                            _logger.info(
                                "UTXO %s not found in this wallet. Please update UTXO's if this is not an "
                                "offline wallet" % to_hexstring(prev_txid)
                            )
                            res = await session.scalars(DbKey.id).filter(
                                DbKey.wallet_id == self.wallet_id,
                                DbKey.address == address,
                            )

                            key_id = res.first()

                            if not key_id:
                                raise WalletError(
                                    "UTXO %s and key with address %s not found in this wallet"
                                    % (to_hexstring(prev_txid), address)
                                )
                            if not value:
                                raise WalletError(
                                    "Input value is zero for address %s. Import or update UTXO's first "
                                    "or import transaction as dictionary" % address
                                )

                amount_total_input += value
                inp_keys, key = await self._objects_by_key_id(key_id)

                tx.add_input(
                    prev_txid,
                    output_n,
                    keys=inp_keys,
                    script_type=unlocking_script_type,
                    sigs_required=self.multisig_n_required,
                    sort=self.sort_keys,
                    compressed=key.compressed,
                    value=value,
                    signatures=signatures,
                    unlocking_script=unlocking_script,
                    address=address,
                    unlocking_script_unsigned=unlocking_script_unsigned,
                    sequence=sequence,
                    locktime_cltv=locktime_cltv,
                    locktime_csv=locktime_csv,
                    witness_type=self.witness_type,
                    key_path=key.path,
                )
        # Calculate fees
        tx.fee = fee
        fee_per_output = None
        tx.size = tx.estimate_size(number_of_change_outputs=number_of_change_outputs)
        if fee is None:
            if not input_arr:
                if not tx.fee_per_kb:
                    tx.fee_per_kb = await srv.estimatefee()
                if tx.fee_per_kb < tx.network.fee_min:
                    tx.fee_per_kb = tx.network.fee_min
                tx.fee = int((tx.size / 1000.0) * tx.fee_per_kb)
                fee_per_output = int((50 / 1000.0) * tx.fee_per_kb)
            else:
                if amount_total_output and amount_total_input:
                    fee = False
                else:
                    tx.fee = 0

        if fee is False:
            tx.change = 0
            tx.fee = int(amount_total_input - amount_total_output)
        else:
            tx.change = int(amount_total_input - (amount_total_output + tx.fee))

        # Skip change if amount is smaller than the dust limit or estimated fee
        if (
            fee_per_output and tx.change < fee_per_output
        ) or tx.change <= tx.network.dust_amount:
            tx.fee += tx.change
            tx.change = 0
        if tx.change < 0:
            raise WalletError(
                "Total amount of outputs is greater then total amount of inputs"
            )
        if tx.change:
            min_output_value = tx.network.dust_amount * 2 + tx.network.fee_min * 4
            if tx.fee and tx.size:
                if not tx.fee_per_kb:
                    tx.fee_per_kb = int((tx.fee * 1000.0) / tx.vsize)
                min_output_value = (
                    tx.fee_per_kb + tx.network.fee_min * 4 + tx.network.dust_amount
                )

            if number_of_change_outputs == 0:
                if (
                    tx.change < amount_total_output / 10
                    or tx.change < min_output_value * 8
                ):
                    number_of_change_outputs = 1
                elif tx.change / 10 > amount_total_output:
                    number_of_change_outputs = random.randint(2, 5)
                else:
                    number_of_change_outputs = random.randint(1, 3)
                    # Prefer 1 and 2 as number of change outputs
                    if number_of_change_outputs == 3:
                        number_of_change_outputs = random.randint(3, 4)
                tx.size = tx.estimate_size(
                    number_of_change_outputs=number_of_change_outputs
                )

            average_change = tx.change // number_of_change_outputs
            if number_of_change_outputs > 1 and average_change < min_output_value:
                raise WalletError(
                    "Not enough funds to create multiple change outputs. Try less change outputs "
                    "or lower fees"
                )

            if self.scheme == "single":
                change_keys = [
                    await self.get_key(account_id=account_id, network=network, change=1)
                ]
            else:
                change_keys = await self.get_keys(
                    account_id=account_id,
                    network=network,
                    change=1,
                    number_of_keys=number_of_change_outputs,
                )

            if number_of_change_outputs > 1:
                rand_prop = tx.change - number_of_change_outputs * min_output_value
                change_amounts = list(
                    (
                        (
                            np.random.dirichlet(
                                np.ones(number_of_change_outputs), size=1
                            )[0]
                            * rand_prop
                        )
                        + min_output_value
                    ).astype(int)
                )
                # Fix rounding problems / small amount differences
                diffs = tx.change - sum(change_amounts)
                for idx, co in enumerate(change_amounts):
                    if co - diffs > min_output_value:
                        change_amounts[idx] += change_amounts.index(co) + diffs
                        break
            else:
                change_amounts = [tx.change]

            for idx, ck in enumerate(change_keys):
                on = tx.add_output(
                    change_amounts[idx], ck.address, encoding=self.encoding
                )
                tx.outputs[on].key_id = ck.key_id

        # Shuffle output order to increase privacy
        if random_output_order:
            tx.shuffle()

        if message:
            lock_script = b"j" + varstr(bytes(message, encoding="utf-8"))
            tx.add_output(0, lock_script=lock_script)

        # Check tx values
        tx.input_total = sum([i.value for i in tx.inputs])
        tx.output_total = sum([o.value for o in tx.outputs])
        if tx.input_total != tx.fee + tx.output_total:
            raise WalletError(
                "Sum of inputs values is not equal to sum of outputs values plus fees"
            )

        tx.txid = tx.signature_hash()[::-1].hex()
        if not tx.fee_per_kb:
            tx.fee_per_kb = int((tx.fee * 1000.0) / tx.vsize)
        if tx.fee_per_kb < tx.network.fee_min:
            raise WalletError(
                "Fee per kB of %d is lower then minimal network fee of %d"
                % (tx.fee_per_kb, tx.network.fee_min)
            )
        elif tx.fee_per_kb > tx.network.fee_max:
            raise WalletError(
                "Fee per kB of %d is higher then maximum network fee of %d"
                % (tx.fee_per_kb, tx.network.fee_max)
            )

        wallet_tx = await WalletTransaction.create(self, tx, account_id=account_id)

        return wallet_tx

    async def transaction_import(
        self, t: GenericTransaction | dict
    ) -> WalletTransaction:
        """
        Import a Transaction into this wallet. Link inputs to wallet keys if possible and return WalletTransaction
        object. Only imports Transaction objects or dictionaries, use
        :func:`transaction_import_raw` method to import a raw transaction.

        :param t: A Transaction object or dictionary
        :type t: Transaction, dict

        :return WalletTransaction:

        """
        # fix this
        if isinstance(t, BaseTransaction):
            rt = await self.transaction_create(
                t.outputs,
                t.inputs,
                fee=t.fee,
                network=t.network.name,
                random_output_order=False,
            )

            rt.tx.block_height = t.block_height
            rt.tx.confirmations = t.confirmations
            rt.tx.witness_type = t.witness_type
            rt.tx.date = t.date
            rt.tx.txid = t.txid
            rt.tx.txhash = t.txhash
            rt.tx.locktime = t.locktime
            rt.tx.version = t.version
            rt.tx.version_int = t.version_int
            rt.tx.block_hash = t.block_hash
            rt.tx.rawtx = t.rawtx
            rt.tx.coinbase = t.coinbase
            rt.tx.flag = t.flag
            rt.tx.size = t.size
            if not t.size:
                rt.tx.size = len(t.raw())
            rt.tx.vsize = t.vsize
            if not t.vsize:
                rt.tx.vsize = rt.tx.size
            rt.tx.fee_per_kb = int((rt.tx.fee / float(rt.tx.vsize)) * 1000)
        elif isinstance(t, dict):
            input_arr = []
            for i in t["inputs"]:
                signatures = [bytes.fromhex(sig) for sig in i["signatures"]]
                script = b"" if "script" not in i else i["script"]
                address = "" if "address" not in i else i["address"]
                input_arr.append(
                    (
                        i["prev_txid"],
                        i["output_n"],
                        None,
                        int(i["value"]),
                        signatures,
                        script,
                        address,
                    )
                )
            output_arr = []
            for o in t["outputs"]:
                output_arr.append((o["address"], int(o["value"])))
            rt = await self.transaction_create(
                output_arr,
                input_arr,
                fee=t["fee"],
                network=t["network"],
                random_output_order=False,
            )
            rt.tx.block_height = t["block_height"]
            rt.tx.confirmations = t["confirmations"]
            rt.tx.witness_type = t["witness_type"]
            rt.tx.date = t["date"]
            rt.tx.txid = t["txid"]
            rt.tx.txhash = t["txhash"]
            rt.tx.locktime = t["locktime"]
            rt.tx.version = t["version"].to_bytes(4, "big")
            rt.tx.version_int = t["version"]
            rt.tx.block_hash = t["block_hash"]
            rt.tx.rawtx = t["raw"]
            rt.tx.coinbase = t["coinbase"]
            rt.tx.flag = t["flag"]
            rt.tx.size = t["size"]
            if not t["size"]:
                rt.tx.size = len(rt.tx.raw())
            rt.tx.vsize = t["vsize"]
            if not rt.tx.vsize:
                rt.tx.vsize = rt.tx.size
            rt.tx.fee_per_kb = int((rt.tx.fee / float(rt.tx.vsize)) * 1000)
        else:
            raise WalletError("Import transaction must be of type Transaction or dict")
        rt.tx.verify()
        return rt

    # can't be bothered updating this right now
    # def transaction_import_raw(self, rawtx: str | bytes, network: str | None = None):
    #     """
    #     Import a raw transaction. Link inputs to wallet keys if possible and return WalletTransaction object

    #     :param rawtx: Raw transaction
    #     :type rawtx: str, bytes
    #     :param network: Network name. Leave empty for default network
    #     :type network: str

    #     :return WalletTransaction:
    #     """

    #     if network is None:
    #         network = self.network.name
    #     if isinstance(rawtx, str):
    #         rawtx = bytes.fromhex(rawtx)

    #     match network:
    #         case "flux":
    #             Klass = FluxTransaction
    #         case _:
    #             Klass = BitcoinTransaction

    #     t_import = Klass.parse_bytes(rawtx, network=network)
    #     rt = self.transaction_create(
    #         t_import.outputs,
    #         t_import.inputs,
    #         network=network,
    #         locktime=t_import.locktime,
    #         random_output_order=False,
    #     )
    #     rt.version_int = t_import.version_int
    #     rt.version = t_import.version
    #     rt.verify()
    #     rt.size = len(rawtx)
    #     rt.calc_weight_units()
    #     rt.fee_per_kb = int((rt.fee / float(rt.vsize)) * 1000)
    #     return rt

    async def send(
        self,
        output_arr: list[tuple[str, int]],
        input_arr: list[tuple[str, int, int, int]] | None = None,
        input_key_id: int | list | None = None,
        account_id: int | None = None,
        network: str | None = None,
        fee: int | None = None,
        min_confirms: int = 1,
        priv_keys: HDKey | list[HDKey] | None = None,
        max_utxos: int | None = None,
        locktime: int = 0,
        offline: bool = True,
        number_of_change_outputs: int = 1,
        message: str = "",
    ) -> WalletTransaction:
        """
        Create a new transaction with specified outputs and push it to the network.
        Inputs can be specified but if not provided they will be selected from wallets utxo's
        Output array is a list of 1 or more addresses and amounts.

        Uses the :func:`transaction_create` method to create a new transaction, and uses a random service client to send the transaction.

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> t = w.send([('1J9GDZMKEr3ZTj8q6pwtMy4Arvt92FDBTb', 200000)], offline=True)
        >>> t
        <WalletTransaction(input_count=1, output_count=2, status=new, network=bitcoin)>
        >>> t.outputs # doctest:+ELLIPSIS
        [<Output(value=..., address=..., type=p2pkh)>, <Output(value=..., address=..., type=p2pkh)>]

        :param output_arr: List of output tuples with address and amount. Must contain at least one item. Example: [('mxdLD8SAGS9fe2EeCXALDHcdTTbppMHp8N', 5000000)]. Address can be an address string, Address object, HDKey object or WalletKey object
        :type output_arr: list
        :param input_arr: List of inputs tuples with reference to a UTXO, a wallet key and value. The format is [(txid, output_n, key_id, value)]
        :type input_arr: list
        :param input_key_id: Limit UTXO's search for inputs to this key ID or list of key IDs. Only valid if no input array is specified
        :type input_key_id: int, list
        :param account_id: Account ID
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param fee: Set fee manually, leave empty to calculate fees automatically. Set fees in the smallest currency  denominator, for example satoshi's if you are using bitcoins. You can also supply a string: 'low', 'normal' or 'high' to determine fees automatically.
        :type fee: int, str
        :param min_confirms: Minimal confirmation needed for an UTXO before it will be included in inputs. Default is 1. Option is ignored if input_arr is provided.
        :type min_confirms: int
        :param priv_keys: Specify extra private key if not available in this wallet
        :type priv_keys: HDKey, list
        :param max_utxos: Maximum number of UTXO's to use. Set to 1 for optimal privacy. Default is None: No maximum
        :type max_utxos: int
        :param locktime: Transaction level locktime. Locks the transaction until a specified block (value from 1 to 5 million) or until a certain time (Timestamp in seconds after 1-jan-1970). Default value is 0 for transactions without locktime
        :type locktime: int
        :param offline: Just return the transaction object and do not send it when offline = True. Default is True
        :type offline: bool
        :param number_of_change_outputs: Number of change outputs to create when there is a change value. Default is 1. Use 0 for random number of outputs: between 1 and 5 depending on send and change amount
        :type number_of_change_outputs: int

        :return WalletTransaction:
        """

        if input_arr and max_utxos and len(input_arr) > max_utxos:
            raise WalletError(
                "Input array contains %d UTXO's but max_utxos=%d parameter specified"
                % (len(input_arr), max_utxos)
            )

        transaction = await self.transaction_create(
            output_arr,
            input_arr,
            input_key_id,
            account_id,
            network,
            fee,
            min_confirms,
            max_utxos,
            locktime,
            number_of_change_outputs,
        )
        transaction.sign(priv_keys)
        # Calculate exact fees and update change output if necessary
        if fee is None and transaction.tx.fee_per_kb and transaction.tx.change:
            fee_exact = transaction.tx.calculate_fee()
            # Recreate transaction if fee estimation more than 10% off
            if (
                fee_exact != self.network.fee_min
                and fee_exact != self.network.fee_max
                and fee_exact
                and abs(
                    (float(transaction.tx.fee) - float(fee_exact)) / float(fee_exact)
                )
                > 0.10
            ):
                _logger.info(
                    "Transaction fee not correctly estimated (est.: %d, real: %d). "
                    "Recreate transaction with correct fee"
                    % (transaction.tx.fee, fee_exact)
                )
                transaction = await self.transaction_create(
                    output_arr,
                    input_arr,
                    input_key_id,
                    account_id,
                    network,
                    fee_exact,
                    min_confirms,
                    max_utxos,
                    locktime,
                    number_of_change_outputs,
                    message,
                )
                transaction.sign(priv_keys)

        transaction.tx.rawtx = transaction.tx.raw()
        transaction.tx.size = len(transaction.tx.rawtx)
        transaction.tx.calc_weight_units()
        transaction.tx.fee_per_kb = int(
            float(transaction.tx.fee) / float(transaction.tx.vsize) * 1000
        )
        transaction.tx.txid = transaction.tx.signature_hash()[::-1].hex()
        await transaction.send(offline)

        return transaction

    async def send_to(
        self,
        to_address: str | Address | HDKey | WalletKey,
        amount: int,
        input_key_id: int | list | None = None,
        account_id: int | None = None,
        network: str | None = None,
        fee: int | None = None,
        min_confirms: int = 1,
        priv_keys: HDKey | list[HDKey] | None = None,
        locktime: int = 0,
        offline: bool = True,
        number_of_change_outputs: int = 1,
        message: str = "",
    ):
        """
        Create transaction and send it with default Service objects :func:`services.sendrawtransaction` method.

        Wrapper for wallet :func:`send` method.

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> t = w.send_to('1J9GDZMKEr3ZTj8q6pwtMy4Arvt92FDBTb', 200000, offline=True)
        >>> t
        <WalletTransaction(input_count=1, output_count=2, status=new, network=bitcoin)>
        >>> t.outputs # doctest:+ELLIPSIS
        [<Output(value=..., address=..., type=p2pkh)>, <Output(value=..., address=..., type=p2pkh)>]

        :param to_address: Single output address as string Address object, HDKey object or WalletKey object
        :type to_address: str, Address, HDKey, WalletKey
        :param amount: Output is the smallest denominator for this network (ie: Satoshi's for Bitcoin), as Value object or value string as accepted by Value class
        :type amount: int, str, Value
        :param input_key_id: Limit UTXO's search for inputs to this key ID or list of key IDs. Only valid if no input array is specified
        :type input_key_id: int, list
        :param account_id: Account ID, default is last used
        :type account_id: int
        :param network: Network name. Leave empty for default network
        :type network: str
        :param fee: Set fee manually, leave empty to calculate fees automatically. Set fees in the smallest currency  denominator, for example satoshi's if you are using bitcoins. You can also supply a string: 'low', 'normal' or 'high' to determine fees automatically.
        :type fee: int, str
        :param min_confirms: Minimal confirmation needed for an UTXO before it will be included in inputs. Default is 1. Option is ignored if input_arr is provided.
        :type min_confirms: int
        :param priv_keys: Specify extra private key if not available in this wallet
        :type priv_keys: HDKey, list
        :param locktime: Transaction level locktime. Locks the transaction until a specified block (value from 1 to 5 million) or until a certain time (Timestamp in seconds after 1-jan-1970). Default value is 0 for transactions without locktime
        :type locktime: int
        :param offline: Just return the transaction object and do not send it when offline = True. Default is True
        :type offline: bool
        :param number_of_change_outputs: Number of change outputs to create when there is a change value. Default is 1. Use 0 for random number of outputs: between 1 and 5 depending on send and change amount
        :type number_of_change_outputs: int

        :return WalletTransaction:
        """

        outputs = [(to_address, amount)]

        return await self.send(
            outputs,
            input_key_id=input_key_id,
            account_id=account_id,
            network=network,
            fee=fee,
            min_confirms=min_confirms,
            priv_keys=priv_keys,
            locktime=locktime,
            offline=offline,
            number_of_change_outputs=number_of_change_outputs,
            message=message,
        )

    async def sweep(
        self,
        to_address,
        account_id=None,
        input_key_id=None,
        network=None,
        max_utxos=999,
        min_confirms=1,
        fee_per_kb=None,
        fee=None,
        locktime=0,
        offline=True,
    ):
        """
        Sweep all unspent transaction outputs (UTXO's) and send them to one or more output addresses.

        Wrapper for the :func:`send` method.

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> t = w.sweep('1J9GDZMKEr3ZTj8q6pwtMy4Arvt92FDBTb')
        >>> t
        <WalletTransaction(input_count=1, output_count=1, status=new, network=bitcoin)>
        >>> t.outputs # doctest:+ELLIPSIS
        [<Output(value=..., address=1J9GDZMKEr3ZTj8q6pwtMy4Arvt92FDBTb, type=p2pkh)>]

        Output to multiple addresses

        >>> to_list = [('1J9GDZMKEr3ZTj8q6pwtMy4Arvt92FDBTb', 100000), (w.get_key(), 0)]
        >>> w.sweep(to_list)
        <WalletTransaction(input_count=1, output_count=2, status=new, network=bitcoin)>

        :param to_address: Single output address or list of outputs in format [(<adddress>, <amount>)]. If you specify a list of outputs, use amount value = 0 to indicate a change output
        :type to_address: str, list
        :param account_id: Wallet's account ID
        :type account_id: int
        :param input_key_id: Limit sweep to UTXO's with this key ID or list of key IDs
        :type input_key_id: int, list
        :param network: Network name. Leave empty for default network
        :type network: str
        :param max_utxos: Limit maximum number of outputs to use. Default is 999
        :type max_utxos: int
        :param min_confirms: Minimal confirmations needed to include utxo
        :type min_confirms: int
        :param fee_per_kb: Fee per kilobyte transaction size, leave empty to get estimated fee costs from Service provider. This option is ignored when the 'fee' option is specified
        :type fee_per_kb: int
        :param fee: Total transaction fee in the smallest denominator (i.e. satoshis). Leave empty to get estimated fee from service providers. You can also supply a string: 'low', 'normal' or 'high' to determine fees automatically.
        :type fee: int, str
        :param locktime: Transaction level locktime. Locks the transaction until a specified block (value from 1 to 5 million) or until a certain time (Timestamp in seconds after 1-jan-1970). Default value is 0 for transactions without locktime
        :type locktime: int
        :param offline: Just return the transaction object and do not send it when offline = True. Default is True
        :type offline: bool

        :return WalletTransaction:
        """

        network, account_id, _ = await self._get_account_defaults(network, account_id)

        utxos = self.utxos(
            account_id=account_id,
            network=network,
            min_confirms=min_confirms,
            key_id=input_key_id,
        )
        utxos = utxos[0:max_utxos]
        input_arr = []
        total_amount = 0
        if not utxos:
            raise WalletError("Cannot sweep wallet, no UTXO's found")
        for utxo in utxos:
            # Skip dust transactions to avoid forced address reuse
            if utxo["value"] <= self.network.dust_amount:
                continue
            input_arr.append(
                (utxo["txid"], utxo["output_n"], utxo["key_id"], utxo["value"])
            )
            total_amount += utxo["value"]
        srv = Service(
            network=network,
            providers=self.providers,
            cache_uri=self.db_cache_uri,
        )

        if isinstance(fee, str):
            n_outputs = 1 if not isinstance(to_address, list) else len(to_address)
            fee_per_kb = await srv.estimatefee(priority=fee)
            tr_size = (
                125
                + (len(input_arr) * (77 + self.multisig_n_required * 72))
                + n_outputs * 30
            )
            fee = 100 + int((tr_size / 1000.0) * fee_per_kb)

        if not fee:
            if fee_per_kb is None:
                fee_per_kb = await srv.estimatefee()
            tr_size = 125 + (len(input_arr) * 125)
            fee = int((tr_size / 1000.0) * fee_per_kb)
        if total_amount - fee <= self.network.dust_amount:
            raise WalletError(
                "Amount to send is smaller then dust amount: %s" % (total_amount - fee)
            )

        if isinstance(to_address, str):
            to_list = [(to_address, total_amount - fee)]
        else:
            to_list = []
            for o in to_address:
                if o[1] == 0:
                    o_amount = total_amount - sum([x[1] for x in to_list]) - fee
                    if o_amount > 0:
                        to_list.append((o[0], o_amount))
                else:
                    to_list.append(o)

        if sum(x[1] for x in to_list) + fee != total_amount:
            raise WalletError(
                "Total amount of outputs does not match total input amount. If you specify a list of "
                "outputs, use amount value = 0 to indicate a change/rest output"
            )

        return await self.send(
            to_list,
            input_arr,
            network=network,
            fee=fee,
            min_confirms=min_confirms,
            locktime=locktime,
            offline=offline,
        )

    def wif(self, is_private=False, account_id=0):
        """
        Return Wallet Import Format string for master private or public key which can be used to import key and
        recreate wallet in other software.

        A list of keys will be exported for a multisig wallet.

        :param is_private: Export public or private key, default is False
        :type is_private: bool
        :param account_id: Account ID of key to export
        :type account_id: bool

        :return list, str:
        """
        if not self.multisig or not self.cosigner:
            if is_private and self.main_key:
                return self.main_key.wif
            else:
                return (
                    self.public_master(account_id=account_id)
                    .key()
                    .wif(
                        is_private=is_private,
                        witness_type=self.witness_type,
                        multisig=self.multisig,
                    )
                )
        else:
            wiflist = []
            for cs in self.cosigner:
                wiflist.append(cs.wif(is_private=is_private))
            return wiflist

    async def public_master(
        self, account_id=None, name=None, as_private=False, network=None
    ):
        """
        Return public master key(s) for this wallet. Use to import in other wallets to sign transactions or create keys.

        For a multisig wallet all public master keys are return as list.

        Returns private key information if available and as_private is True is specified

        >>> w = Wallet('fluxwallet_legacy_wallet_test')
        >>> w.public_master().wif
        'xpub6D2qEr8Z8WYKKns2xZYyyvvRviPh1NKt1kfHwwfiTxJwj7peReEJt3iXoWWsr8tXWTsejDjMfAezM53KVFVkSZzA5i2pNy3otprtYUvh4u1'

        :param account_id: Account ID of key to export
        :type account_id: int
        :param name: Optional name for account key
        :type name: str
        :param as_private: Export public or private key, default is False
        :type as_private: bool
        :param network: Network name. Leave empty for default network
        :type network: str

        :return list of WalletKey, WalletKey:
        """
        if self.main_key and self.main_key.key_type == "single":
            key = self.main_key
            return key if as_private else key.public()
        elif not self.cosigner:
            depth = -self.key_depth + self.depth_public_master
            key = await self.key_for_path(
                [],
                depth,
                name=name,
                account_id=account_id,
                network=network,
                cosigner_id=self.cosigner_id,
            )
            return key if as_private else key.public()
        else:
            pm_list = []
            for cs in self.cosigner:
                pm_list.append(cs.public_master(account_id, name, as_private, network))
            return pm_list

    def transaction_load(self, txid=None, filename=None):
        """
        Load transaction object from file which has been stored with the :func:`Transaction.save` method.

        Specify transaction ID or filename.

        :param txid: Transaction ID. Transaction object will be read from .fluxwallet datadir
        :type txid: str
        :param filename: Name of transaction object file
        :type filename: str

        :return Transaction:
        """
        if not filename and not txid:
            raise WalletError("Please supply filename or txid")
        elif not filename and txid:
            p = Path(FW_DATA_DIR, "%s.tx" % txid)
        else:
            p = Path(filename)
            if not p.parent or str(p.parent) == ".":
                p = Path(FW_DATA_DIR, filename)
        f = p.open("rb")
        t = pickle.load(f)
        f.close()
        return self.transaction_import(t)

    async def info(self, detail=3):
        """
        Prints wallet information to standard output

        :param detail: Level of detail to show. Specify a number between 0 and 5, with 0 low detail and 5 highest detail
        :type detail: int
        """

        print("=== WALLET ===")
        print(" ID                             %s" % self.wallet_id)
        print(" Name                           %s" % self.name)
        print(" Owner                          %s" % self.owner)
        print(" Scheme                         %s" % self.scheme)
        print(" Multisig                       %s" % self.multisig)
        if self.multisig:
            print(
                " Multisig Wallet IDs            %s"
                % str([w.wallet_id for w in self.cosigner]).strip("[]")
            )
            print(" Cosigner ID                    %s" % self.cosigner_id)
        print(" Witness type                   %s" % self.witness_type)
        print(" Main network                   %s" % self.network.name)
        print(" Latest update                  %s" % self.last_updated)

        if self.multisig:
            print("\n= Multisig Public Master Keys =")
            for cs in self.cosigner:
                print(
                    "%5s %3s %-70s %-6s %-8s %s"
                    % (
                        cs.cosigner_id,
                        cs.main_key.key_id,
                        cs.wif(is_private=False),
                        cs.scheme,
                        "main" if cs.main_key.is_private else "cosigner",
                        "*" if cs.cosigner_id == self.cosigner_id else "",
                    )
                )

            print(
                "For main keys a private master key is available in this wallet to sign transactions. "
                "* cosigner key for this wallet"
            )

        if detail and self.main_key:
            print("\n= Wallet Master Key =")
            print(" ID                             %s" % self.main_key_id)
            print(" Private                        %s" % self.main_key.is_private)
            print(" Depth                          %s" % self.main_key.depth)

        balances = await self._balance_update()
        if detail > 1:
            for nw in await self.networks():
                print("\n- NETWORK: %s -" % nw.name)
                print("- - Keys")
                if detail < 4:
                    ds = [self.key_depth]
                elif detail < 5:
                    if self.purpose == 45:
                        ds = [0, self.key_depth]
                    else:
                        ds = [0, self.depth_public_master, self.key_depth]
                else:
                    ds = range(8)
                for d in ds:
                    is_active = True
                    if detail > 3:
                        is_active = False
                    for key in await self.keys(
                        depth=d, network=nw.name, is_active=is_active
                    ):
                        print(
                            "%5s %-28s %-45s %-25s %25s"
                            % (
                                key.id,
                                key.path,
                                key.address,
                                key.name,
                                Value.from_satoshi(key.balance, network=nw).str_unit(
                                    currency_repr="symbol"
                                ),
                            )
                        )

                if detail > 2:
                    include_new = False
                    if detail > 3:
                        include_new = True
                    accounts = await self.accounts(network=nw.name)
                    if not accounts:
                        accounts = [0]
                    for account_id in accounts:
                        txs = await self.transactions(
                            include_new=include_new,
                            account_id=account_id,
                            network=nw.name,
                            as_dict=True,
                        )
                        print(
                            "\n- - Transactions Account %d (%d)"
                            % (account_id, len(txs))
                        )
                        for tx in txs:
                            spent = " "
                            address = tx["address"]
                            if not tx["address"]:
                                address = "nulldata"
                            elif "spent" in tx and tx["spent"] is False:
                                spent = "U"
                            status = ""
                            if tx["status"] not in ["confirmed", "unconfirmed"]:
                                status = tx["status"]
                            print(
                                "%64s %43s %8d %21s %s %s"
                                % (
                                    tx["txid"],
                                    address,
                                    tx["confirmations"],
                                    Value.from_satoshi(
                                        tx["value"], network=nw
                                    ).str_unit(currency_repr="symbol"),
                                    spent,
                                    status,
                                )
                            )

        print("\n= Balance Totals (includes unconfirmed) =")
        for na_balance in balances:
            print(
                "%-20s %-20s %20s"
                % (
                    na_balance["network"],
                    "(Account %s)" % na_balance["account_id"],
                    Value.from_satoshi(
                        na_balance["balance"], network=na_balance["network"]
                    ).str_unit(currency_repr="symbol"),
                )
            )
        print("\n")

    async def as_dict(self, include_private=False):
        """
        Return wallet information in dictionary format

        :param include_private: Include private key information in dictionary
        :type include_private: bool

        :return dict:
        """

        keys = []
        transactions = []
        for netw in await self.networks():
            for key in await self.keys(
                network=netw.name, include_private=include_private, as_dict=True
            ):
                keys.append(key)

            if self.multisig:
                for t in await self.transactions(
                    include_new=True, account_id=0, network=netw.name
                ):
                    transactions.append(t.as_dict())
            else:
                accounts = await self.accounts(network=netw.name)
                if not accounts:
                    accounts = [0]
                for account_id in accounts:
                    for t in await self.transactions(
                        include_new=True, account_id=account_id, network=netw.name
                    ):
                        transactions.append(t.as_dict())

        return {
            "wallet_id": self.wallet_id,
            "name": self.name,
            "owner": self._owner,
            "scheme": self.scheme,
            "witness_type": self.witness_type,
            "main_network": self.network.name,
            "main_balance": self.balance(),
            "main_balance_str": self.balance(as_string=True),
            "balances": self._balances,
            "default_account_id": self.default_account_id,
            "multisig_n_required": self.multisig_n_required,
            "cosigner_wallet_ids": [w.wallet_id for w in self.cosigner],
            "cosigner_public_masters": [
                w.public_master().key().wif() for w in self.cosigner
            ],
            "sort_keys": self.sort_keys,
            "main_key_id": self.main_key_id,
            "encoding": self.encoding,
            "keys": keys,
            "transactions": transactions,
        }

    def as_json(self, include_private=False):
        """
        Get current key as json formatted string

        :param include_private: Include private key information in JSON
        :type include_private: bool

        :return str:
        """
        adict = self.as_dict(include_private=include_private)
        return json.dumps(adict, indent=4, default=str)
