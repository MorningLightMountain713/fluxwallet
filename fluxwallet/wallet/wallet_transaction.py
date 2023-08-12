from __future__ import annotations

import pickle
import time
from itertools import groupby
from operator import itemgetter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fluxwallet.wallet import Wallet

from enum import Enum
from typing import TypeVar

from rich.pretty import pprint
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from fluxwallet.db_new import (
    DbKey,
    DbTransaction,
    DbTransactionInput,
    DbTransactionOutput,
)

# from fluxwallet.db_new import
from fluxwallet.encoding import *
from fluxwallet.keys import Address, HDKey, check_network_and_key
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
)
from fluxwallet.values import Value, value_to_satoshi
from fluxwallet.wallet.errors import WalletError

_logger = logging.getLogger(__name__)


# class TxDirection(Enum):
#     INBOUND = "INBOUND"
#     OUTBOUND = "OUTBOUND"


GenericTransaction = TypeVar("GenericTransaction", FluxTransaction, BitcoinTransaction)


class WalletTransaction:
    """
    Used as attribute of Wallet class. Child of Transaction object with extra reference to
    wallet and database object.

    All WalletTransaction items are stored in a database
    """

    def __init__(
        self,
        hdwallet: Wallet,
        transaction: GenericTransaction,
        addresslist: list[str],
        *,
        account_id: int | None = None,
    ):
        """
        Initialize WalletTransaction object with reference to a Wallet object

        :param hdwallet: Wallet object, wallet name or ID
        :type hdWallet: HDwallet, str, int
        :param account_id: Account ID
        :type account_id: int
        :param args: Arguments for HDWallet parent class
        :type args: args
        :param kwargs: Keyword arguments for Wallet parent class
        :type kwargs: kwargs
        """
        # assert isinstance(hdwallet, Wallet)

        self.hdwallet = hdwallet
        self.tx = transaction

        self.status = "confirmed" if self.tx.confirmations else "new"

        self.pushed: bool = False
        self.error: str | None = None

        # this refers to the wallet, so can be both
        self.outgoing_tx: bool | None = None
        self.incoming_tx: bool | None = None

        self.account_id: int = (
            self.hdwallet.default_account_id if account_id is None else account_id
        )

        if hdwallet.witness_type in ["segwit", "p2sh-segwit"]:
            self.tx.witness_type = hdwallet.witness_type
        else:
            # isn't this the default anyway?
            self.tx.witness_type = "legacy"

        self.outgoing_tx = bool(
            [i.address for i in self.tx.inputs if i.address in addresslist]
        )
        self.incoming_tx = bool(
            [o.address for o in self.tx.outputs if o.address in addresslist]
        )

    @classmethod
    async def create(
        cls,
        hdwallet: Wallet,
        transaction: GenericTransaction,
        account_id: int | None = None,
    ) -> WalletTransaction:
        addresslist = await hdwallet.addresslist()

        self = WalletTransaction(
            hdwallet, transaction, addresslist, account_id=account_id
        )

        return self

    def __repr__(self):
        return (
            "<WalletTransaction(input_count=%d, output_count=%d, status=%s, network=%s)>"
            % (
                len(self.tx.inputs),
                len(self.tx.outputs),
                self.status,
                self.tx.network.name,
            )
        )

    # probably don'r need this anymore
    def __deepcopy__(self, memo):
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result
        self_dict = self.__dict__
        for k, v in self_dict.items():
            if k != "hdwallet":
                setattr(result, k, deepcopy(v, memo))
        result.hdwallet = self.hdwallet
        return result

    # @classmethod
    # async def from_transaction(cls, hdwallet: Wallet, t: GenericTransaction):
    #     """
    #     Create WalletTransaction object from Transaction object

    #     :param hdwallet: Wallet object, wallet name or ID
    #     :type hdwallet: HDwallet, str, int
    #     :param t: Specify Transaction object
    #     :type t: Transaction

    #     :return WalletClass:
    #     """

    #     return await cls.create(
    #         hdwallet=hdwallet,
    #         inputs=t.inputs,
    #         outputs=t.outputs,
    #         locktime=t.locktime,
    #         version=t.version,
    #         network=t.network.name,
    #         fee=t.fee,
    #         fee_per_kb=t.fee_per_kb,
    #         size=t.size,
    #         txid=t.txid,
    #         txhash=t.txhash,
    #         date=t.date,
    #         confirmations=t.confirmations,
    #         block_height=t.block_height,
    #         block_hash=t.block_hash,
    #         input_total=t.input_total,
    #         output_total=t.output_total,
    #         rawtx=t.rawtx,
    #         status=t.status,
    #         coinbase=t.coinbase,
    #         verified=t.verified,
    #         flag=t.flag,
    #         expiry_height=t.expiry_height,
    #     )

    @classmethod
    async def from_txid(
        cls, hdwallet: Wallet, txid: str, addresslist: list[str] | None
    ):
        """
        Read single transaction from database with given transaction ID / transaction hash

        :param hdwallet: Wallet object
        :type hdwallet: Wallet
        :param txid: Transaction hash as hexadecimal string
        :type txid: str, bytes

        :return WalletClass:

        """
        if not addresslist:
            addresslist = await hdwallet.addresslist()

        async with hdwallet.db.get_session() as session:
            # If txid is unknown add it to database, else update
            # start = time.perf_counter()
            res = await session.scalars(
                select(DbTransaction).filter(
                    DbTransaction.wallet_id == hdwallet.wallet_id,
                    DbTransaction.txid == to_bytes(txid),
                )
            )
            db_tx: DbTransaction = res.first()
            if not db_tx:
                return

            await db_tx.awaitable_attrs.inputs
            await db_tx.awaitable_attrs.outputs
            # print(f"Tiem to get full dbtx", time.perf_counter() - start)

            fee_per_kb = None
            if db_tx.fee and db_tx.size:
                fee_per_kb = int((db_tx.fee / db_tx.size) * 1000)

            network = Network(db_tx.network_name)

            inputs = []
            for inp in db_tx.inputs:
                sequence = 0xFFFFFFFF
                if inp.sequence:
                    sequence = inp.sequence
                inp_keys = []

                if inp.key_id:
                    key = await hdwallet.key(inp.key_id)

                    if key.key_type == "multisig":
                        res = await session.scalars(
                            select(DbKey).filter_by(id=key.key_id)
                        )
                        db_key = res.first()

                        for ck in db_key.multisig_children:
                            inp_keys.append(ck.child_key.public.hex())
                    else:
                        inp_keys = key.key()

        inputs.append(
            Input(
                prev_txid=inp.prev_txid,
                output_n=inp.output_n,
                keys=inp_keys,
                unlocking_script=inp.script,
                script_type=inp.script_type,
                sequence=sequence,
                index_n=inp.index_n,
                value=inp.value,
                double_spend=inp.double_spend,
                witness_type=inp.witness_type,
                network=network,
                address=inp.address,
                witnesses=inp.witnesses,
            )
        )

        outputs = []
        for out in db_tx.outputs:
            address = ""
            public_key = b""

            if out.key_id:
                key = await hdwallet.key(out.key_id)
                address = key.address

                if key.key_type != "multisig":
                    if key.key() and not isinstance(key.key(), Address):
                        public_key = key.key().public_hex

            outputs.append(
                Output(
                    value=out.value,
                    address=address,
                    public_key=public_key,
                    lock_script=out.script,
                    spent=out.spent,
                    output_n=out.output_n,
                    script_type=out.script_type,
                    network=network,
                )
            )

        match network.name:
            case "flux":
                klass = FluxTransaction
            case _:
                klass = BitcoinTransaction

        tx = klass(
            inputs=inputs,
            outputs=outputs,
            locktime=db_tx.locktime,
            version=db_tx.version,
            network=network,
            fee=db_tx.fee,
            fee_per_kb=fee_per_kb,
            size=db_tx.size,
            txid=to_hexstring(txid),
            date=db_tx.date,
            confirmations=db_tx.confirmations,
            block_height=db_tx.block_height,
            input_total=db_tx.input_total,
            output_total=db_tx.output_total,
            rawtx=db_tx.raw,
            status=db_tx.status,
            coinbase=db_tx.coinbase,
            verified=db_tx.verified,
        )

        return cls(hdwallet, tx, addresslist, account_id=db_tx.account_id)

    def to_transaction(self) -> GenericTransaction:
        return self.tx

    def sign(
        self,
        keys: HDKey | str | None = None,
        index_n: int = 0,
        multisig_key_n: int | None = None,
        hash_type: int = SIGHASH_ALL,
        fail_on_unknown_key: bool = False,
        replace_signatures: bool = False,
    ):
        """
        Sign this transaction. Use existing keys from wallet or use keys argument for extra keys.

        :param keys: Extra private keys to sign the transaction
        :type keys: HDKey, str
        :param index_n: Transaction index_n to sign
        :type index_n: int
        :param multisig_key_n: Index number of key for multisig input for segwit transactions. Leave empty if not known. If not specified all possibilities will be checked
        :type multisig_key_n: int
        :param hash_type: Hashtype to use, default is SIGHASH_ALL
        :type hash_type: int
        :param fail_on_unknown_key: Method fails if public key from signature is not found in public key list
        :type fail_on_unknown_key: bool
        :param replace_signatures: Replace signature with new one if already signed.
        :type replace_signatures: bool

        :return None:
        """
        priv_key_list_arg = []
        if keys:
            key_paths = [ti.key_path for ti in self.tx.inputs if ti.key_path[0] == "m"]

            if not isinstance(keys, list):
                keys = [keys]

            for priv_key in keys:
                if not isinstance(priv_key, HDKey):
                    if isinstance(priv_key, str) and len(str(priv_key).split(" ")) > 4:
                        priv_key = HDKey.from_passphrase(
                            priv_key, network=self.tx.network
                        )
                    else:
                        priv_key = HDKey(priv_key, network=self.tx.network.name)

                priv_key_list_arg.append((None, priv_key))

                if key_paths and priv_key.depth == 0 and priv_key.key_type != "single":
                    for key_path in key_paths:
                        priv_key_list_arg.append(
                            (key_path, priv_key.subkey_for_path(key_path))
                        )

        for ti in self.tx.inputs:
            priv_key_list = []

            for key_path, priv_key in priv_key_list_arg:
                if (
                    not key_path or key_path == ti.key_path
                ) and priv_key not in priv_key_list:
                    priv_key_list.append(priv_key)

            priv_key_list += [k for k in ti.keys if k.is_private]

            self.tx.sign(
                priv_key_list,
                ti.index_n,
                multisig_key_n,
                hash_type,
                fail_on_unknown_key,
                replace_signatures,
            )

        self.tx.verify()
        self.error = ""

    async def send(self, offline: bool = False) -> None:
        """
        Verify and push transaction to network. Update UTXO's in database after successful send

        :param offline: Just return the transaction object and do not send it when offline = True. Default is False
        :type offline: bool

        :return None:

        """

        self.error = None
        if not self.tx.verified or not self.tx.verify():
            self.error = "Cannot verify transaction"
            return

        if offline:
            return

        srv = Service(
            network=self.hdwallet.network.name,
            providers=self.hdwallet.providers,
            cache_uri=self.hdwallet.db_cache_uri,
        )
        res = await srv.sendrawtransaction(self.tx.raw_hex())

        if not res:
            self.error = "Cannot send transaction. %s" % srv.errors
            return

        if "txid" not in res:
            self.error = "Transaction not sent, unknown response from service providers"
            return

        _logger.info("Successfully pushed transaction, result: %s" % res)

        self.tx.txid = res["txid"]
        self.status = "unconfirmed"
        self.pushed = True

        await self.store()

        async with self.hdwallet.db.get_session() as session:
            # Update db: Update spent UTXO's, add transaction to database
            for inp in self.tx.inputs:
                txid = inp.prev_txid
                res = await session.scalars(
                    select(DbTransactionOutput)
                    .join(DbTransaction)
                    .filter(
                        DbTransaction.txid == txid,
                        DbTransactionOutput.output_n == inp.output_n_int,
                        DbTransactionOutput.spent.is_(False),
                    )
                )
                utxos = res.all()

                for u in utxos:
                    u.spent = True

            await session.commit()

        await self.hdwallet._balance_update(network=self.tx.network.name)

    async def sync(self) -> None:
        """Sync this wallet transaction data with the database"""

        async with self.hdwallet.db.get_session() as session:
            res = await session.scalars(
                select(DbTransaction).filter(
                    DbTransaction.wallet_id == self.hdwallet.wallet_id,
                    DbTransaction.txid == bytes.fromhex(self.tx.txid),
                )
            )
            db_tx = res.first()

            if not db_tx:
                return

        self.tx.block_height = (
            db_tx.block_height if db_tx.block_height else self.tx.block_height
        )

        self.tx.confirmations = (
            db_tx.confirmations if db_tx.confirmations else self.tx.confirmations
        )

        self.tx.date = db_tx.date if db_tx.date else self.tx.date

        self.status = db_tx.status if db_tx.status else self.status

    async def store(self):
        """
        Store this transaction to database

        :return int: Transaction index number
        """
        async with self.hdwallet.db.get_session() as session:
            # If txid is unknown add it to database, else update
            res = await session.scalars(
                select(DbTransaction).filter(
                    DbTransaction.wallet_id == self.hdwallet.wallet_id,
                    DbTransaction.txid == bytes.fromhex(self.tx.txid),
                )
            )
            db_tx = res.first()

            if not db_tx:
                res = await session.scalars(
                    select(DbTransaction).filter(
                        DbTransaction.wallet_id.is_(None),
                        DbTransaction.txid == bytes.fromhex(self.tx.txid),
                    )
                )
                db_tx = res.first()

                if db_tx:
                    db_tx.wallet_id = self.hdwallet.wallet_id

            rolled_back = False
            if not db_tx:
                # seems dodgey
                version = 4 if self.tx.network.name == "flux" else 1

                new_tx = DbTransaction(
                    wallet_id=self.hdwallet.wallet_id,
                    version=version,
                    txid=bytes.fromhex(self.tx.txid),
                    block_height=self.tx.block_height,
                    size=self.tx.size,
                    confirmations=self.tx.confirmations,
                    date=self.tx.date,
                    fee=self.tx.fee,
                    status=self.status,
                    input_total=self.tx.input_total,
                    output_total=self.tx.output_total,
                    network_name=self.tx.network.name,
                    raw=self.tx.rawtx,
                    verified=self.tx.verified,
                    account_id=self.account_id,
                    coinbase=self.tx.coinbase,
                    expiry_height=self.tx.expiry_height,
                )
                session.add(new_tx)
                try:
                    await session.commit()

                except IntegrityError:
                    print("ROLLEDBACK")
                    _logger.info(
                        f"Rolling back this transaction, already stored for tx: {self.tx.txid}"
                    )
                    await session.rollback()
                    rolled_back = True

                except Exception as e:  # pragma: no cover
                    _logger.warning(f"Tx store failure tx: {e}")

                txidn = new_tx.id

            if db_tx or rolled_back:
                if rolled_back:
                    res = await session.scalars(
                        select(DbTransaction).filter(
                            DbTransaction.wallet_id == self.hdwallet.wallet_id,
                            DbTransaction.txid == bytes.fromhex(self.tx.txid),
                        )
                    )
                    db_tx = res.first()
                    _logger.info(f"Found previously stored transaction: {self.tx.txid}")

                txidn = db_tx.id
                db_tx.block_height = (
                    self.tx.block_height if self.tx.block_height else db_tx.block_height
                )
                db_tx.confirmations = (
                    self.tx.confirmations
                    if self.tx.confirmations
                    else db_tx.confirmations
                )
                db_tx.date = self.tx.date if self.tx.date else db_tx.date
                db_tx.fee = self.tx.fee if self.tx.fee else db_tx.fee
                db_tx.status = self.status if self.status else db_tx.status
                db_tx.input_total = (
                    self.tx.input_total if self.tx.input_total else db_tx.input_total
                )
                db_tx.output_total = (
                    self.tx.output_total if self.tx.output_total else db_tx.output_total
                )
                db_tx.network_name = (
                    self.tx.network.name if self.tx.network.name else db_tx.network_name
                )
                db_tx.raw = self.tx.rawtx if self.tx.rawtx else db_tx.raw
                db_tx.verified = self.tx.verified
                db_tx.coinbase = self.tx.coinbase

                await session.commit()

            for ti in self.tx.inputs:
                res = await session.scalars(
                    select(DbKey).filter_by(
                        wallet_id=self.hdwallet.wallet_id, address=ti.address
                    )
                )
                tx_key = res.first()

                key_id = None
                if tx_key:
                    key_id = tx_key.id
                    tx_key.used = True

                res = await session.scalars(
                    select(DbTransactionInput).filter_by(
                        transaction_id=txidn, index_n=ti.index_n
                    )
                )
                tx_input = res.first()

                if not tx_input:
                    witnesses = int_to_varbyteint(len(ti.witnesses)) + b"".join(
                        [bytes(varstr(w)) for w in ti.witnesses]
                    )
                    new_tx_item = DbTransactionInput(
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
                    session.add(new_tx_item)
                elif key_id:
                    tx_input.key_id = key_id
                    if ti.value:
                        tx_input.value = ti.value
                    if ti.prev_txid:
                        tx_input.prev_txid = ti.prev_txid
                    if ti.unlocking_script:
                        tx_input.script = ti.unlocking_script

                rolled_back = False
                try:
                    await session.commit()

                except IntegrityError:
                    print("ROLLEDBACK")
                    _logger.info(
                        f"Rolling back this transaction, already stored for tx: {self.tx.txid}"
                    )
                    await session.rollback()
                    rolled_back = True

                except Exception as e:  # pragma: no cover
                    _logger.warning(f"Tx store failure tx: {e}")

                if rolled_back and key_id:
                    res = await session.scalars(
                        select(DbTransactionInput).filter_by(
                            transaction_id=txidn, index_n=ti.index_n
                        )
                    )
                    tx_input = res.first()

                    tx_input.key_id = key_id
                    if ti.value:
                        tx_input.value = ti.value
                    if ti.prev_txid:
                        tx_input.prev_txid = ti.prev_txid
                    if ti.unlocking_script:
                        tx_input.script = ti.unlocking_script

                    await session.commit()

            for to in self.tx.outputs:
                res = await session.scalars(
                    select(DbKey).filter_by(
                        wallet_id=self.hdwallet.wallet_id, address=to.address
                    )
                )
                tx_key = res.first()
                key_id = None

                if tx_key:
                    key_id = tx_key.id
                    tx_key.used = True

                spent = to.spent
                res = await session.scalars(
                    select(DbTransactionOutput).filter_by(
                        transaction_id=txidn, output_n=to.output_n
                    )
                )
                tx_output = res.first()

                if not tx_output:
                    new_tx_item = DbTransactionOutput(
                        transaction_id=txidn,
                        output_n=to.output_n,
                        key_id=key_id,
                        address=to.address,
                        value=to.value,
                        spent=spent,
                        script=to.lock_script,
                        script_type=to.script_type,
                    )
                    session.add(new_tx_item)
                elif key_id:
                    tx_output.key_id = key_id
                    tx_output.spent = spent if spent is not None else tx_output.spent

                rolled_back = False
                try:
                    await session.commit()

                except IntegrityError:
                    print("ROLLEDBACK")
                    _logger.info(
                        f"Rolling back this transaction, already stored for tx: {self.tx.txid}"
                    )
                    await session.rollback()
                    rolled_back = True

                except Exception as e:  # pragma: no cover
                    _logger.warning(f"Tx store failure tx: {e}")

                if rolled_back and key_id:
                    res = await session.scalars(
                        select(DbTransactionOutput).filter_by(
                            transaction_id=txidn, output_n=to.output_n
                        )
                    )
                    tx_output = res.first()

                    tx_output.key_id = key_id
                    tx_output.spent = spent if spent is not None else tx_output.spent
                    await session.commit()

        return txidn

    async def store_old(self):
        """
        Store this transaction to database

        :return int: Transaction index number
        """
        async with self.hdwallet.db.get_session() as session:
            # If txid is unknown add it to database, else update
            res = await session.scalars(
                select(DbTransaction).filter(
                    DbTransaction.wallet_id == self.hdwallet.wallet_id,
                    DbTransaction.txid == bytes.fromhex(self.tx.txid),
                )
            )
            db_tx = res.first()

            if not db_tx:
                res = await session.scalars(
                    select(DbTransaction).filter(
                        DbTransaction.wallet_id.is_(None),
                        DbTransaction.txid == bytes.fromhex(self.tx.txid),
                    )
                )
                db_tx = res.first()

                if db_tx:
                    db_tx.wallet_id = self.hdwallet.wallet_id

            rolled_back = False
            if not db_tx:
                # seems dodgey
                version = 4 if self.tx.network.name == "flux" else 1

                new_tx = DbTransaction(
                    wallet_id=self.hdwallet.wallet_id,
                    version=version,
                    txid=bytes.fromhex(self.tx.txid),
                    block_height=self.tx.block_height,
                    size=self.tx.size,
                    confirmations=self.tx.confirmations,
                    date=self.tx.date,
                    fee=self.tx.fee,
                    status=self.status,
                    input_total=self.tx.input_total,
                    output_total=self.tx.output_total,
                    network_name=self.tx.network.name,
                    raw=self.tx.rawtx,
                    verified=self.tx.verified,
                    account_id=self.account_id,
                    coinbase=self.tx.coinbase,
                    expiry_height=self.tx.expiry_height,
                )
                session.add(new_tx)
                try:
                    await session.commit()

                except IntegrityError:
                    print("ROLLEDBACK")
                    _logger.info(
                        f"Rolling back this transaction, already stored for tx: {self.tx.txid}"
                    )
                    await session.rollback()
                    rolled_back = True

                except Exception as e:  # pragma: no cover
                    _logger.warning(f"Tx store failure tx: {e}")

                txidn = new_tx.id

            if db_tx or rolled_back:
                if rolled_back:
                    res = await session.scalars(
                        select(DbTransaction).filter(
                            DbTransaction.wallet_id == self.hdwallet.wallet_id,
                            DbTransaction.txid == bytes.fromhex(self.tx.txid),
                        )
                    )
                    db_tx = res.first()
                    _logger.info(f"Found previously stored transaction: {self.tx.txid}")

                txidn = db_tx.id
                db_tx.block_height = (
                    self.tx.block_height if self.tx.block_height else db_tx.block_height
                )
                db_tx.confirmations = (
                    self.tx.confirmations
                    if self.tx.confirmations
                    else db_tx.confirmations
                )
                db_tx.date = self.tx.date if self.tx.date else db_tx.date
                db_tx.fee = self.tx.fee if self.tx.fee else db_tx.fee
                db_tx.status = self.status if self.status else db_tx.status
                db_tx.input_total = (
                    self.tx.input_total if self.tx.input_total else db_tx.input_total
                )
                db_tx.output_total = (
                    self.tx.output_total if self.tx.output_total else db_tx.output_total
                )
                db_tx.network_name = (
                    self.tx.network.name if self.tx.network.name else db_tx.network_name
                )
                db_tx.raw = self.tx.rawtx if self.tx.rawtx else db_tx.raw
                db_tx.verified = self.tx.verified
                db_tx.coinbase = self.tx.coinbase

                await session.commit()

            for ti in self.tx.inputs:
                res = await session.scalars(
                    select(DbKey).filter_by(
                        wallet_id=self.hdwallet.wallet_id, address=ti.address
                    )
                )
                tx_key = res.first()

                key_id = None
                if tx_key:
                    key_id = tx_key.id
                    tx_key.used = True

                res = await session.scalars(
                    select(DbTransactionInput).filter_by(
                        transaction_id=txidn, index_n=ti.index_n
                    )
                )
                tx_input = res.first()

                if not tx_input:
                    witnesses = int_to_varbyteint(len(ti.witnesses)) + b"".join(
                        [bytes(varstr(w)) for w in ti.witnesses]
                    )
                    new_tx_item = DbTransactionInput(
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
                    session.add(new_tx_item)
                elif key_id:
                    tx_input.key_id = key_id
                    if ti.value:
                        tx_input.value = ti.value
                    if ti.prev_txid:
                        tx_input.prev_txid = ti.prev_txid
                    if ti.unlocking_script:
                        tx_input.script = ti.unlocking_script

                rolled_back = False
                try:
                    await session.commit()

                except IntegrityError:
                    print("ROLLEDBACK")
                    _logger.info(
                        f"Rolling back this transaction, already stored for tx: {self.tx.txid}"
                    )
                    await session.rollback()
                    rolled_back = True

                except Exception as e:  # pragma: no cover
                    _logger.warning(f"Tx store failure tx: {e}")

                if rolled_back and key_id:
                    res = await session.scalars(
                        select(DbTransactionInput).filter_by(
                            transaction_id=txidn, index_n=ti.index_n
                        )
                    )
                    tx_input = res.first()

                    tx_input.key_id = key_id
                    if ti.value:
                        tx_input.value = ti.value
                    if ti.prev_txid:
                        tx_input.prev_txid = ti.prev_txid
                    if ti.unlocking_script:
                        tx_input.script = ti.unlocking_script

                    await session.commit()

            for to in self.tx.outputs:
                res = await session.scalars(
                    select(DbKey).filter_by(
                        wallet_id=self.hdwallet.wallet_id, address=to.address
                    )
                )
                tx_key = res.first()
                key_id = None

                if tx_key:
                    key_id = tx_key.id
                    tx_key.used = True

                spent = to.spent
                res = await session.scalars(
                    select(DbTransactionOutput).filter_by(
                        transaction_id=txidn, output_n=to.output_n
                    )
                )
                tx_output = res.first()

                if not tx_output:
                    new_tx_item = DbTransactionOutput(
                        transaction_id=txidn,
                        output_n=to.output_n,
                        key_id=key_id,
                        address=to.address,
                        value=to.value,
                        spent=spent,
                        script=to.lock_script,
                        script_type=to.script_type,
                    )
                    session.add(new_tx_item)
                elif key_id:
                    tx_output.key_id = key_id
                    tx_output.spent = spent if spent is not None else tx_output.spent

                rolled_back = False
                try:
                    await session.commit()

                except IntegrityError:
                    print("ROLLEDBACK")
                    _logger.info(
                        f"Rolling back this transaction, already stored for tx: {self.tx.txid}"
                    )
                    await session.rollback()
                    rolled_back = True

                except Exception as e:  # pragma: no cover
                    _logger.warning(f"Tx store failure tx: {e}")

                if rolled_back and key_id:
                    res = await session.scalars(
                        select(DbTransactionOutput).filter_by(
                            transaction_id=txidn, output_n=to.output_n
                        )
                    )
                    tx_output = res.first()

                    tx_output.key_id = key_id
                    tx_output.spent = spent if spent is not None else tx_output.spent
                    await session.commit()

        return txidn

    def info(self):
        """
        Print Wallet transaction information to standard output. Include send information.
        """
        self.tx.info()

        print("Pushed to network: %s" % self.pushed)
        print("Wallet: %s" % self.hdwallet.name)

        if self.error:
            print("Errors: %s" % self.error)

        print("\n")

    async def export(self, skip_change=True):
        """
        Export this transaction as list of tuples in the following format:
            (transaction_date, transaction_hash, in/out, addresses_in, addresses_out, value, fee)

        A transaction with multiple inputs or outputs results in multiple tuples.

        :param skip_change: Do not include outputs to own wallet (default). Please note: So if this is set to True, then an internal transfer is not exported.
        :type skip_change: boolean

        :return list of tuple:
        """
        mut_list = []
        wlt_addresslist = await self.hdwallet.addresslist()

        input_addresslist = [i.address for i in self.tx.inputs]
        if self.outgoing_tx:
            fee_per_output = self.fee / len(self.tx.outputs)

            for o in self.tx.outputs:
                o_value = -o.value
                if o.address in wlt_addresslist:
                    if skip_change:
                        continue
                    elif self.incoming_tx:
                        o_value = 0
                mut_list.append(
                    (
                        self.tx.date,
                        self.tx.txid,
                        "out",
                        input_addresslist,
                        o.address,
                        o_value,
                        fee_per_output,
                    )
                )
        else:
            for o in self.tx.outputs:
                if o.address not in wlt_addresslist:
                    continue
                mut_list.append(
                    (
                        self.tx.date,
                        self.tx.txid,
                        "in",
                        input_addresslist,
                        o.address,
                        o.value,
                        0,
                    )
                )

        return mut_list

    # def save(self, filename=None):
    #     """
    #     Store transaction object as file, so it can be imported in fluxwallet later with the :func:`load` method.

    #     :param filename: Location and name of file, leave empty to store transaction in fluxwallet data directory: .fluxwallet/<transaction_id.tx)
    #     :type filename: str

    #     :return:
    #     """
    #     if not filename:
    #         p = Path(FW_DATA_DIR, "%s.tx" % self.txid)
    #     else:
    #         p = Path(filename)
    #         if not p.parent or str(p.parent) == ".":
    #             p = Path(FW_DATA_DIR, filename)

    #     f = p.open("wb")
    #     t = self.to_transaction()
    #     pickle.dump(t, f)
    #     f.close()

    # def delete(self):
    #     """
    #     Delete this transaction from database.

    #     WARNING: Results in incomplete wallets, transactions will NOT be automatically downloaded again when scanning or updating wallet. In normal situations only used to remove old unconfirmed transactions

    #     :return int: Number of deleted transactions
    #     """

    #     session = self.hdwallet._session
    #     txid = bytes.fromhex(self.txid)
    #     tx_query = session.query(DbTransaction).filter_by(txid=txid)
    #     tx = tx_query.scalar()
    #     session.query(DbTransactionOutput).filter_by(transaction_id=tx.id).delete()
    #     session.query(DbTransactionInput).filter_by(transaction_id=tx.id).delete()
    #     session.query(DbKey).filter_by(latest_txid=txid).update(
    #         {DbKey.latest_txid: None}
    #     )
    #     res = tx_query.delete()
    #     self.hdwallet._commit()
    #     return res
