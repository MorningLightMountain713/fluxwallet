import logging

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from fluxwallet.config.config import DEFAULT_WITNESS_TYPE
from fluxwallet.db_new import Db, DbKey, DbNetwork
from fluxwallet.encoding import *
from fluxwallet.keys import Address, HDKey
from fluxwallet.networks import Network
from fluxwallet.values import Value
from fluxwallet.wallet.errors import WalletError

DEFAULT_WITNESS_TYPE: str

_logger = logging.getLogger(__name__)


class WalletKey:
    """
    Used as attribute of Wallet class. Contains HDKey class, and adds extra wallet related information such as
    key ID, name, path and balance.

    All WalletKeys are stored in a database
    """

    @staticmethod
    async def from_db_key(
        key_id: int, async_session: AsyncSession, *, hdkey: HDKey | None = None
    ):
        async with async_session as session:
            if db_key := await session.get(DbKey, key_id):
                await db_key.awaitable_attrs.wallet
                return WalletKey(db_key, hdkey)
            else:
                raise WalletError(f"Key with id {key_id} not found")

    @staticmethod
    async def from_hdkey(
        name: str,
        wallet_id: int,
        async_session: AsyncSession,
        *,
        key: HDKey | Address | str | bytes | None = None,
        account_id: int = 0,
        network: str | None = None,
        change: int = 0,
        purpose: int = 44,
        parent_id: int = 0,
        path: str = "m",
        key_type: str | None = None,
        encoding: str | None = None,
        witness_type: str | None = DEFAULT_WITNESS_TYPE,
        multisig: bool = False,
        cosigner_id: int | None = None,
    ):
        """
        Create WalletKey from a HDKey object or key.

        Normally you don't need to call this method directly. Key creation is handled by the Wallet class.

        >>> w = wallet_create_or_open('hdwalletkey_test')
        >>> wif = 'xprv9s21ZrQH143K2mcs9jcK4EjALbu2z1N9qsMTUG1frmnXM3NNCSGR57yLhwTccfNCwdSQEDftgjCGm96P29wGGcbBsPqZH85iqpoHA7LrqVy'
        >>> db_key = WalletKey.from_key('import_key', w.wallet_id, w._session, wif)
        >>> self.dbkey.address
        '1MwVEhGq6gg1eeSrEdZom5bHyPqXtJSnPg'
        >>> db_key # doctest:+ELLIPSIS
        <WalletKey(key_id=..., name=import_key, wif=xprv9s21ZrQH143K2mcs9jcK4EjALbu2z1N9qsMTUG1frmnXM3NNCSGR57yLhwTccfNCwdSQEDftgjCGm96P29wGGcbBsPqZH85iqpoHA7LrqVy, path=m)>

        :param name: New key name
        :type name: str
        :param wallet_id: ID of wallet where to store key
        :type wallet_id: int
        :param session: Required Sqlalchemy Session object
        :type session: sqlalchemy.orm.session.Session
        :param key: Optional key in any format accepted by the HDKey class
        :type key: str, int, byte, HDKey
        :param account_id: Account ID for specified key, default is 0
        :type account_id: int
        :param network: Network of specified key
        :type network: str
        :param change: Use 0 for normal key, and 1 for change key (for returned payments)
        :type change: int
        :param purpose: BIP0044 purpose field, default is 44
        :type purpose: int
        :param parent_id: Key ID of parent, default is 0 (no parent)
        :type parent_id: int
        :param path: BIP0044 path of given key, default is 'm' (masterkey)
        :type path: str
        :param key_type: Type of key, single or BIP44 type
        :type key_type: str
        :param encoding: Encoding used for address, i.e.: base58 or bech32. Default is base58
        :type encoding: str
        :param witness_type: Witness type used when creating transaction script: legacy, p2sh-segwit or segwit.
        :type witness_type: str
        :param multisig: Specify if key is part of multisig wallet, used for create keys and key representations such as WIF and addreses
        :type multisig: bool
        :param cosigner_id: Set this if you would like to create keys for other cosigners.
        :type cosigner_id: int

        :return WalletKey: WalletKey object
        """
        key_is_address = False
        if isinstance(key, HDKey):
            hd_key = key
            if network is None:
                network = hd_key.network.name
            elif network != hd_key.network.name:
                raise WalletError(
                    "Specified network and key network should be the same"
                )
        elif isinstance(key, Address):
            hd_key = key
            key_is_address = True
            if network is None:
                network = hd_key.network.name
            elif network != hd_key.network.name:
                raise WalletError(
                    "Specified network and key network should be the same"
                )
        else:  # str | bytes
            if network is None:
                network = DEFAULT_NETWORK
            hd_key = HDKey(import_key=key, network=network)

        if not encoding and witness_type:
            encoding = get_encoding_from_witness(witness_type)

        script_type = script_type_default(witness_type, multisig)

        async with async_session as session:
            if not key_is_address:
                res = await session.scalars(
                    select(DbKey).filter(
                        DbKey.wallet_id == wallet_id,
                        DbKey.wif
                        == hd_key.wif(
                            witness_type=witness_type,
                            multisig=multisig,
                            is_private=True,
                        ),
                    )
                )

                existing_db_key = res.first()

                if existing_db_key:
                    _logger.warning(
                        "Key already exists in this wallet. Key ID: %d"
                        % existing_db_key.id
                    )
                    await existing_db_key.awaitable_attrs.wallet
                    return WalletKey(existing_db_key, hd_key)

                if key_type != "single" and hd_key.depth != len(path.split("/")) - 1:
                    if path == "m" and hd_key.depth > 1:
                        path = "M"

                address = hd_key.address(encoding=encoding, script_type=script_type)

                res = await session.scalars(
                    select(DbKey).where(
                        DbKey.wallet_id == wallet_id,
                        or_(
                            DbKey.public == hd_key.public_byte,
                            DbKey.wif
                            == hd_key.wif(
                                witness_type=witness_type,
                                multisig=multisig,
                                is_private=False,
                            ),
                            DbKey.address == address,
                        ),
                    )
                )
                db_key = res.first()

                if db_key:
                    db_key.wif = hd_key.wif(
                        witness_type=witness_type, multisig=multisig, is_private=True
                    )
                    db_key.is_private = True
                    db_key.private = hd_key.private_byte
                    db_key.public = hd_key.public_byte
                    db_key.path = path

                    await session.commit()
                    await db_key.awaitable_attrs.wallet

                    return WalletKey(db_key, hd_key)

                new_db_key = DbKey(
                    name=name[:80],
                    wallet_id=wallet_id,
                    public=hd_key.public_byte,
                    private=hd_key.private_byte,
                    purpose=purpose,
                    account_id=account_id,
                    depth=hd_key.depth,
                    change=change,
                    address_index=hd_key.child_index,
                    wif=hd_key.wif(
                        witness_type=witness_type, multisig=multisig, is_private=True
                    ),
                    address=address,
                    parent_id=parent_id,
                    compressed=hd_key.compressed,
                    is_private=hd_key.is_private,
                    path=path,
                    key_type=key_type,
                    network_name=network,
                    encoding=encoding,
                    cosigner_id=cosigner_id,
                )
            else:
                res = await session.scalars(
                    select(DbKey).where(
                        DbKey.wallet_id == wallet_id, DbKey.address == hd_key.address
                    )
                )
                existing_db_key = res.first()

                if existing_db_key:
                    _logger.warning(
                        "Key with ID %s already exists" % existing_db_key.id
                    )

                    await existing_db_key.awaitable_attrs.wallet
                    return WalletKey(existing_db_key, hd_key)

                new_db_key = DbKey(
                    name=name[:80],
                    wallet_id=wallet_id,
                    purpose=purpose,
                    account_id=account_id,
                    depth=hd_key.depth,
                    change=change,
                    address=hd_key.address(),
                    parent_id=parent_id,
                    compressed=hd_key.compressed,
                    is_private=False,
                    path=path,
                    key_type=key_type,
                    network_name=network,
                    encoding=encoding,
                    cosigner_id=cosigner_id,
                )

            await session.merge(DbNetwork(name=network))
            session.add(new_db_key)

            await session.commit()
            await new_db_key.awaitable_attrs.wallet

        return WalletKey(new_db_key, hd_key)

    # def _commit(self):
    #     try:
    #         self._session.commit()
    #     except Exception:
    #         self._session.rollback()
    #         raise

    def __init__(self, db_key: DbKey, hdkey: HDKey | None = None):
        """
        Initialize WalletKey with specified ID, get information from database.

        :param key_id: ID of key as mentioned in database
        :type key_id: int
        :param session: Required Sqlalchemy Session object
        :type session: sqlalchemy.orm.session.Session
        :param hdkey: Optional HDKey object. Specify HDKey object if available for performance
        :type hdkey: HDKey

        """
        self.dbkey = db_key
        self.hdkey = hdkey

        # fix this
        if hdkey and isinstance(hdkey, HDKey):
            assert not self.dbkey.public or self.dbkey.public == hdkey.public_byte
            assert not self.dbkey.private or self.dbkey.private == hdkey.private_byte

        self.key_id = self.dbkey.id
        self._name = self.dbkey.name
        self.wallet_id = self.dbkey.wallet_id
        self.key_public = None if not self.dbkey.public else self.dbkey.public
        self.key_private = None if not self.dbkey.private else self.dbkey.private
        self.account_id = self.dbkey.account_id
        self.change = self.dbkey.change
        self.address_index = self.dbkey.address_index
        self.wif = self.dbkey.wif
        self.address = self.dbkey.address
        self._balance = self.dbkey.balance
        self.purpose = self.dbkey.purpose
        self.parent_id = self.dbkey.parent_id
        self.is_private = self.dbkey.is_private
        self.path = self.dbkey.path
        self.wallet = self.dbkey.wallet
        self.network_name = self.dbkey.network_name

        if not self.network_name:
            self.network_name = self.dbkey.wallet.network_name

        self.network = Network(self.network_name)
        self.depth = self.dbkey.depth
        self.key_type = self.dbkey.key_type
        self.compressed = self.dbkey.compressed
        self.encoding = self.dbkey.encoding
        self.cosigner_id = self.dbkey.cosigner_id
        self.used = self.dbkey.used

    def __repr__(self):
        return "<WalletKey(key_id=%d, name=%s, wif=%s, path=%s)>" % (
            self.key_id,
            self.name,
            self.wif,
            self.path,
        )

    @property
    def name(self):
        """
        Return name of wallet key

        :return str:
        """
        return self._name

    # @name.setter
    # def name(self, value):
    #     """
    #     Set key name, update in database

    #     :param value: Name for this key
    #     :type value: str

    #     :return str:
    #     """

    #     self._name = value
    #     self.dbkey.name = value
    #     self._commit()

    def key(self) -> HDKey:
        """
        Get HDKey object for current WalletKey

        :return HDKey:
        """

        self.hdkey = None
        if self.key_type == "multisig":
            self.hdkey = []
            for kc in self.dbkey.multisig_children:
                self.hdkey.append(
                    HDKey.from_wif(
                        kc.child_key.wif,
                        network=kc.child_key.network_name,
                        compressed=self.compressed,
                    )
                )
        if self.hdkey is None and self.wif:
            self.hdkey = HDKey.from_wif(
                self.wif, network=self.network_name, compressed=self.compressed
            )
        return self.hdkey

    def balance(self, as_string=False):
        """
        Get total value of unspent outputs

        :param as_string: Specify 'string' to return a string in currency format
        :type as_string: bool

        :return float, str: Key balance
        """

        if as_string:
            return Value.from_satoshi(self._balance, network=self.network).str_unit()
        else:
            return self._balance

    def public(self):
        """
        Return current key as public WalletKey object with all private information removed

        :return WalletKey:
        """
        pub_key = self
        pub_key.is_private = False
        pub_key.key_private = None

        if self.key():
            pub_key.wif = self.key().wif()
        if self.hdkey:
            self.hdkey = pub_key.hdkey.public()

        self.dbkey = None

        return pub_key

    def as_dict(self, include_private=False):
        """
        Return current key information as dictionary

        :param include_private: Include private key information in dictionary
        :type include_private: bool

        """

        kdict = {
            "id": self.key_id,
            "key_type": self.key_type,
            "network": self.network.name,
            "is_private": self.is_private,
            "name": self.name,
            "key_public": "" if not self.key_public else self.key_public.hex(),
            "account_id": self.account_id,
            "parent_id": self.parent_id,
            "depth": self.depth,
            "change": self.change,
            "address_index": self.address_index,
            "address": self.address,
            "encoding": self.encoding,
            "path": self.path,
            "balance": self.balance(),
            "balance_str": self.balance(as_string=True),
        }
        if include_private:
            kdict.update(
                {
                    "key_private": self.key_private.hex(),
                    "wif": self.wif,
                }
            )
        return kdict
