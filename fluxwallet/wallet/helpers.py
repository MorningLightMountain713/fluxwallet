import logging

from sqlalchemy import delete, select, update

from fluxwallet.db_new import (
    Db,
    DbKey,
    DbKeyMultisigChildren,
    DbTransaction,
    DbTransactionInput,
    DbTransactionOutput,
    DbWallet,
)
from fluxwallet.wallet import Wallet

_logger = logging.getLogger(__name__)


async def wallets_list(db_uri=None, include_cosigners=False):
    """
    List Wallets from database

    :param db_uri: URI of the database
    :type db_uri: str

    :param include_cosigners: Child wallets for multisig wallets are for internal use only and are skipped by default
    :type include_cosigners: bool

    :return dict: Dictionary of wallets defined in database
    """
    async with Db(db_uri=db_uri) as session:
        stmt_wallets = select(DbWallet).order_by(DbWallet.id)

        db_wallets = await session.scalars(stmt_wallets)

        wallets = []
        for w in db_wallets:
            if w.parent_id and not include_cosigners:
                continue
            wallets.append(
                {
                    "id": w.id,
                    "name": w.name,
                    "owner": w.owner,
                    "network": w.network_name,
                    "purpose": w.purpose,
                    "scheme": w.scheme,
                    "main_key_id": w.main_key_id,
                    "parent_id": w.parent_id,
                }
            )

    return wallets


# test this out
# from sqlalchemy import inspect

# def object_as_dict(obj):
#     return {
#         c.key: getattr(obj, c.key)
#         for c in inspect(obj).mapper.column_attrs
#     }

# user = session.query(User).first()

# d = object_as_dict(user)


async def wallet_exists(wallet, db_uri=None):
    """
    Check if Wallets is defined in database

    :param wallet: Wallet ID as integer or Wallet Name as string
    :type wallet: int, str
    :param db_uri: URI of the database
    :type db_uri: str

    :return bool: True if wallet exists otherwise False
    """

    if wallet in [x["name"] for x in await wallets_list(db_uri)]:
        return True
    if isinstance(wallet, int) and wallet in [
        x["id"] for x in await wallets_list(db_uri)
    ]:
        return True
    return False


async def wallet_create_or_open(
    name,
    keys="",
    owner="",
    network=None,
    account_id=0,
    purpose=None,
    scheme="bip32",
    sort_keys=True,
    password="",
    witness_type=None,
    encoding=None,
    multisig=None,
    sigs_required=None,
    cosigner_id=None,
    key_path=None,
    db_uri=None,
):
    """
    Create a wallet with specified options if it doesn't exist, otherwise just open

    Returns Wallet object

    See Wallets class create method for option documentation
    """

    if await wallet_exists(name, db_uri=db_uri):
        if keys or owner or password or witness_type or key_path:
            _logger.warning("Opening existing wallet, extra options are ignored")
        return await Wallet(name, db_uri=db_uri).open()
    else:
        return await Wallet.create(
            name,
            keys,
            owner,
            network,
            account_id,
            purpose,
            scheme,
            sort_keys,
            password,
            witness_type,
            encoding,
            multisig,
            sigs_required,
            cosigner_id,
            key_path,
            db_uri=db_uri,
        )


async def wallet_delete(
    wallet: Wallet | int | str, db_uri: str | None = None, force: bool = False
):
    """
    Delete wallet and associated keys and transactions from the database. If wallet has unspent outputs it raises a
    WalletError exception unless 'force=True' is specified

    :param wallet: Wallet ID as integer or Wallet Name as string
    :type wallet: int, str
    :param db_uri: URI of the database
    :type db_uri: str
    :param force: If set to True wallet will be deleted even if unspent outputs are found. Default is False
    :type force: bool

    :return int: Number of rows deleted, so 1 if successful
    """
    async with Db(db_uri=db_uri) as session:
        if isinstance(wallet, int) or wallet.isdigit():
            res = await session.scalars(select(DbWallet).filter_by(id=wallet))
        else:
            res = await session.scalars(select(DbWallet).filter_by(name=wallet))

        w = res.first()

        if not w:
            raise WalletError("Wallet '%s' not found" % wallet)

        wallet_id = w.id

        # Delete co-signer wallets if this is a multisig wallet
        for cw in await session.scalars(
            select(DbWallet).filter_by(parent_id=wallet_id)
        ):
            await wallet_delete(cw.id, db_uri=db_uri, force=force)

        # Delete keys from this wallet and update transactions (remove key_id)
        ks = await session.scalars(select(DbKey).filter_by(wallet_id=wallet_id))
        if bool([k for k in ks if k.balance and k.is_private]) and not force:
            raise WalletError(
                "Wallet still has unspent outputs. Use 'force=True' to delete this wallet"
            )

        k_ids = [k.id for k in ks]

        statements = []

        statements.append(
            update(DbTransactionOutput)
            .where(DbTransactionOutput.key_id.in_(k_ids))
            .values(key_id=None)
        )

        statements.append(
            update(DbTransactionInput)
            .where(DbTransactionInput.key_id.in_(k_ids))
            .values(key_id=None)
        )

        statements.append(
            delete(DbKeyMultisigChildren).where(
                DbKeyMultisigChildren.parent_id.in_(k_ids)
            )
        )

        statements.append(
            delete(DbKeyMultisigChildren).where(
                DbKeyMultisigChildren.child_id.in_(k_ids)
            )
        )

        statements.append(delete(DbKey).where(DbKey.wallet_id == wallet))

        for statement in statements:
            await session.execute(statement)

        statements = []

        txs = await session.scalars(
            select(DbTransaction).filter_by(wallet_id=wallet_id)
        )

        for tx in txs:
            statements.append(
                delete(DbTransactionOutput).where(
                    DbTransactionOutput.transaction_id == tx.id
                )
            )
            statements.append(
                delete(DbTransactionInput).where(
                    DbTransactionInput.transaction_id == tx.id
                )
            )

        statements.append(
            delete(DbTransaction).where(DbTransaction.wallet_id == wallet_id)
        )

        for statement in statements:
            await session.execute(statement)

        statements = []

        # Unlink transactions from this wallet (remove wallet_id)
        # stmt_unlink_txs = (
        #     update(DbTransaction)
        #     .where(DbTransaction.wallet_id == wallet_id)
        #     .values(wallet_id=None)
        # )

        # await session.execute(stmt_unlink_txs)
        stmt_del_wallet = delete(DbWallet).where(DbWallet.id == wallet_id)

        res = await session.execute(stmt_del_wallet)
        await session.commit()

    _logger.info("Wallet '%s' deleted" % wallet)

    return res


async def wallet_empty(wallet: Wallet | int | str, db_uri: str | None = None):
    """
    Remove all generated keys and transactions from wallet. Does not delete the wallet itself or the masterkey,
    so everything can be recreated.

    :param wallet: Wallet ID as integer or Wallet Name as string
    :type wallet: int, str
    :param db_uri: URI of the database
    :type db_uri: str

    :return bool: True if successful
    """

    async with Db(db_uri=db_uri) as session:
        if isinstance(wallet, int) or wallet.isdigit():
            res = await session.scalars(select(DbWallet).filter_by(id=wallet))
        else:
            res = await session.scalars(select(DbWallet).filter_by(name=wallet))

        w = res.first()

        if not w:
            raise WalletError("Wallet '%s' not found" % wallet)

        wallet_id = w.id

        ks = await session.scalars(
            select(DbKey).where(DbKey.wallet_id == wallet_id, DbKey.parent_id != 0)
        )

        k_ids = [k.id for k in ks]

        statements = []

        statements.append(
            update(DbTransactionOutput)
            .where(DbTransactionOutput.key_id.in_(k_ids))
            .values(key_id=None)
        )

        statements.append(
            update(DbTransactionInput)
            .where(DbTransactionInput.key_id.in_(k_ids))
            .values(key_id=None)
        )

        statements.append(
            delete(DbKeyMultisigChildren).where(
                DbKeyMultisigChildren.parent_id.in_(k_ids)
            )
        )

        statements.append(
            delete(DbKeyMultisigChildren).where(
                DbKeyMultisigChildren.child_id.in_(k_ids)
            )
        )

        for statement in statements:
            await session.execute(statement)

        statements = []

        txs = await session.scalars(
            select(DbTransaction).filter_by(wallet_id=wallet_id)
        )

        for tx in txs:
            statements.append(
                delete(DbTransactionOutput).where(
                    DbTransactionOutput.transaction_id == tx.id
                )
            )
            statements.append(
                delete(DbTransactionInput).where(
                    DbTransactionInput.transaction_id == tx.id
                )
            )

        statements.append(
            delete(DbTransaction).where(DbTransaction.wallet_id == wallet_id)
        )

        for statement in statements:
            await session.execute(statement)

        await session.commit()

        _logger.info("All keys and transactions from wallet '%s' deleted" % wallet)

        return True


async def wallet_delete_if_exists(wallet, db_uri=None, force=False):
    """
    Delete wallet and associated keys from the database. If wallet has unspent outputs it raises a WalletError exception
    unless 'force=True' is specified. If the wallet does not exist return False

    :param wallet: Wallet ID as integer or Wallet Name as string
    :type wallet: int, str
    :param db_uri: URI of the database
    :type db_uri: str
    :param force: If set to True wallet will be deleted even if unspent outputs are found. Default is False
    :type force: bool

    :return int: Number of rows deleted, so 1 if successful
    """

    if await wallet_exists(wallet, db_uri):
        return await wallet_delete(wallet, db_uri, force)
    return False


def normalize_path(path):
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
