# -*- coding: utf-8 -*-
#
#    fluxwallet - Python Cryptocurrency Library
#    BitGo Client
#    © 2017-2019 July - 1200 Web Development <http://1200wd.com/>
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

import asyncio
import binascii
import logging
from collections.abc import Iterator
from contextlib import aclosing
from datetime import datetime
from decimal import Decimal

import httpx
from rich.pretty import pprint

from fluxwallet.config.config import FLUXWALLET_VERSION
from fluxwallet.main import MAX_TRANSACTIONS
from fluxwallet.services.baseclient import BaseClient, ClientError
from fluxwallet.transactions import BaseTransaction, FluxTransaction

_logger = logging.getLogger(__name__)

PROVIDERNAME = "flux"
LIMIT_TX = 49


class FluxClient(BaseClient):
    def __init__(self, network: str, base_url: str, denominator: int, *args):
        super().__init__(network, PROVIDERNAME, base_url, denominator, *args)

    def load_tx(self, tx: dict) -> FluxTransaction:
        """Load a transaction from the api into a python object

        Args:
            tx (dict): The result from API call

        Returns:
            Transaction: a parsed transaction
        """

        confirmations = tx.get("confirmations", 0)
        status = "unconfirmed"
        if confirmations:
            status = "confirmed"
        witness_type = "legacy"

        coinbase = bool(tx.get("isCoinBase", False))
        fee = tx.get("fees", 0)
        value_in = tx.get("valueIn", 0)

        t = FluxTransaction(
            locktime=tx["locktime"],
            version=tx["version"],
            network="flux",
            fee=fee,
            size=tx["size"],
            txid=tx["txid"],
            date=None if not confirmations else datetime.utcfromtimestamp(tx["time"]),
            confirmations=confirmations,
            block_height=tx["blockheight"],
            status=status,
            input_total=value_in,
            coinbase=coinbase,
            output_total=tx["valueOut"],
            witness_type=witness_type,
            expiry_height=tx["nExpiryHeight"],
        )

        if coinbase:
            t.add_input(prev_txid=b"\00" * 32, output_n=0, value=0)
        else:
            index_n = 0
            for ti in tx["vin"]:
                t.add_input(
                    prev_txid=binascii.unhexlify(ti["txid"]),
                    output_n=ti["vout"],
                    unlocking_script=ti["scriptSig"]["hex"],
                    index_n=index_n,
                    value=ti["valueSat"],
                    address=ti["addr"],
                    sequence=ti["sequence"],
                    strict=True,
                )
                index_n += 1

        for to in tx["vout"]:
            try:
                addr = to["scriptPubKey"]["addresses"][0]
            except KeyError:
                addr = ""

            t.add_output(
                value=int(Decimal(to["value"]) * 100000000),
                address=addr,
                lock_script=to["scriptPubKey"]["hex"],
                spent=bool(to["spentTxId"]),
                output_n=to["n"],
                spending_txid=to["spentTxId"],
                spending_index_n=to["spentIndex"],
                strict=True,
            )

        return t

    async def getutxos(
        self, address: str, after_txid: str = "", limit: int = MAX_TRANSACTIONS
    ):
        utxos = []

        query_params = {"address": address}
        res = await self.do_get("explorer/utxo", params=query_params)

        after_height = 0

        for utxo in res["data"]:
            if utxo["txid"] == after_txid:
                after_height = int(utxo["height"])

            # need to go look up the tx to get size / fee etc etc.
            utxos.append(
                {
                    "address": utxo["address"],
                    "txid": utxo["txid"],
                    "confirmations": utxo["confirmations"],
                    "output_n": utxo["vout"],
                    "input_n": 0,
                    "block_height": int(utxo["height"]),
                    # "fee": None,
                    # "size": 0,
                    "value": utxo["satoshis"],
                    "script": utxo["scriptPubKey"],
                }
            )
        after_tx_filter = (
            lambda x: x["block_height"] >= after_height and x["txid"] != after_txid
        )
        utxos = list(filter(after_tx_filter, utxos))

        return utxos[::-1][:limit]

    async def estimatefee(self, blocks):
        # Fix this
        return 3

    async def blockcount(self) -> int:
        # return self.compose_request("daemon/getblockcount")["data"]
        # res: dict = await anext(self.do_get("daemon/getblockcount"))
        # daemon is slower to update that explorer, so using explorer
        res: dict = await anext(
            self.do_get("sync", base_url="https://explorer.runonflux.io/api/")
        )
        print(res)
        return res.get("height")
        # return res.get("data", 0)

    async def sendrawtransaction(self, rawtx: str) -> dict[str, dict]:
        # res = self.compose_request(
        #     "daemon/sendrawtransaction",
        #     post_data={"hexstring": rawtx},
        #     http_verb="post",
        # )
        res = await self.do_post(
            "daemon/sendrawtransaction", post_data={"hexstring": rawtx}
        )

        try:
            res.raise_for_status()
        except httpx.RequestError:
            return

        tx_res = res.json()

        print(tx_res)

        return {
            "txid": tx_res["data"],
        }

    # async def gettransaction(self, txid: str):
    #     # variables = {"txid": txid}
    #     # res = self.compose_request("daemon", "getrawtransaction", variables=variables)
    #     base = "https://explorer.runonflux.io/"
    #     res = self.compose_request(f"api/tx/{txid}", base=base)

    #     tx = self.load_tx(res)
    #     # pprint(tx.as_dict())
    #     return tx

    async def get_transactions(self, txids: list[str]):
        txs: list[dict] = []

        paths = [f"tx/{txid}" for txid in txids]

        tx_gen = self.do_get(paths, base_url="https://explorer.runonflux.io/api/")
        # {'status': 404, 'url': '/api/tx/', 'error': 'Not found'}
        async for tx_group in tx_gen:
            txs.extend(tx_group)

        txs = sorted(txs, key=lambda x: x["blockheight"])
        tx_objects = [self.load_tx(tx) for tx in txs]

        return tx_objects

    async def get_transactions_by_address(
        self, address: str, after_tx_index: int = 0, limit: int = 0
    ) -> Iterator[list[FluxTransaction]]:
        # get lastest txid and count
        params = {"from": 0, "to": 1, "noAsm": 1}

        # https://explorer.runonflux.io/api/addrs/t1XvGeQCfYMhfagYb3GmbKRajNEjpPRZHkB/txs?from=0&to=1&noAsm=1&noScriptSig=1

        # don't use generator for single items, or just use for to get the single item so we don't have to use aclosing
        async with aclosing(
            self.do_get(
                f"/api/addrs/{address}/txs",
                base_url="https://explorer.runonflux.io",
                params=params,
            )
        ) as gen:
            res: dict = await anext(gen)

        first_tx: list[dict] = res.get("items", [])
        tx_count: int = res.get("totalItems", 0)

        if not first_tx:
            return

        # this should always be greater than 0, but, you konw
        new_txs = max(0, tx_count - after_tx_index)

        if not new_txs:
            return

        if new_txs == 1:
            yield [self.load_tx(first_tx[0])]

        # this is always 1, we already have 0
        from_tx = 1

        tx_generator = self.do_get(
            paths=f"/api/addrs/{address}/txs",
            base_url="https://explorer.runonflux.io",
            pages=(from_tx, new_txs),
            chunksize=1,
            params={"noAsm": 1},
        )

        async for batch in tx_generator:
            txs = []
            # fix this
            if first_tx:
                txs.append(first_tx[0])
                first_tx = None

            for result in batch:
                txs.extend(result.get("items"))

            yield [self.load_tx(tx) for tx in txs]

    # async def get_pages_for_item(
    #     self,
    #     item: str,
    #     client: httpx.AsyncClient,
    #     endpoint: str,
    #     params: dict,
    #     pages: int,
    # ) -> list:
    #     results = []
    #     tasks = [
    #         client.send(
    #             client.build_request(
    #                 "GET",
    #                 endpoint,
    #                 params=params | {"pageNum": page},
    #             )
    #         )
    #         for page in range(2, pages + 1)
    #     ]

    #     to_retry = []
    #     for coro in asyncio.as_completed(tasks):
    #         try:
    #             result = await coro
    #         except httpx.RequestError as e:
    #             pprint(type(e))
    #             pprint(e.request)
    #             # retry
    #             # add to missing... then retry them all
    #             print(f"Failure... Adding {e.request.url} to be retried")
    #             to_retry.append(e.request.url)
    #         else:
    #             data: dict = result.json()

    #         results.extend(data.get(item))

    #     retries = [
    #         client.send(client.build_request("GET", page_url)) for page_url in to_retry
    #     ]
    #     # this is highly regarded
    #     for coro in asyncio.as_completed(retries):
    #         result = await coro
    #         data: dict = result.json()
    #         results.extend(data.get(item))

    #     return results

    async def do_post(
        self,
        endpoint: str,
        *,
        base_url: str | None = None,
        post_data: dict[str, str] | None = None,
    ) -> httpx.Response:
        if not base_url:
            base_url = self.base_url

        headers = {
            "User-Agent": f"fluxwallet/{FLUXWALLET_VERSION}",
            "Accept": "application/json",
        }
        transport = httpx.AsyncHTTPTransport(retries=5)

        async with httpx.AsyncClient(
            base_url=base_url, headers=headers, transport=transport
        ) as client:
            # need to retry if failure or do something
            return await client.post(endpoint, data=post_data)

    async def do_get(
        self,
        paths: list[str] | str,
        *,
        base_url: str | None = None,
        params: dict[str, str] | None = None,
        chunksize: int = 10,
        pages: int | tuple[int] | None = None,
    ) -> Iterator[list[dict]]:
        if not base_url:
            base_url = self.base_url

        if not params:
            params = {}

        headers = {
            "User-Agent": f"fluxwallet/{FLUXWALLET_VERSION}",
            "Accept": "application/json",
        }

        transport = httpx.AsyncHTTPTransport(retries=6)
        timeout = httpx.Timeout(10.0, connect=5.0)

        async with httpx.AsyncClient(
            base_url=base_url, headers=headers, transport=transport, timeout=timeout
        ) as client:
            # this doesn't mix in the client options (have to build request)
            # req = httpx.Request(http_verb, uri)

            single_result = False
            if isinstance(paths, str):
                paths = [paths]
                single_result = True

            # this is really implementation dependent. Should be passed in from
            # upper layer i.e. pageNum and from/to
            if not pages:
                tasks = [client.get(path, params=params) for path in paths]
            else:
                # this is super fucking ugly
                # don't think this is used anymore??!??
                if isinstance(pages, int):
                    ...
                    # tasks = [
                    #     client.get(
                    #         paths[0],
                    #         params=params | {"pageNum": page},
                    #     )
                    #     # this doesn't make sense - it's coupled with a particular api
                    #     for page in range(2, pages + 1)
                    # ]
                else:  # tuple (from, to)
                    single_result = False
                    RESPONSE_SIZE = 20

                    from_tx, to_tx = pages

                    increments = list(range(from_tx, to_tx, RESPONSE_SIZE))

                    if to_tx % RESPONSE_SIZE:
                        increments.append(to_tx)

                    windows = [*zip(increments, increments[1::])]

                    tasks = [
                        client.get(
                            paths[0],
                            params=params | {"from": window[0], "to": window[1]},
                        )
                        for window in windows
                    ]

            results = []
            to_retry = []
            count = 0

            for coro in asyncio.as_completed(tasks):
                try:
                    result = await coro
                except (httpx.RequestError, httpx.ReadError) as e:
                    print("REQUEST / READ ERROR")
                    to_retry.append(e.request.url)
                else:
                    result = result.json()
                    if single_result:
                        # print("HTTX RESULT")
                        # pprint(result)
                        yield result

                    results.append(result)

                    pages_total = result.get("pagesTotal", 0)

                    if not pages and pages_total:
                        async for result in self.do_get(
                            paths, base_url=base_url, params=params, pages=pages_total
                        ):
                            yield result

                    count += 1

                if count == chunksize:
                    yield results
                    count = 0
                    results = []

            if count > 0:
                yield results

            if to_retry:
                print(f"Warning: Retrying {len(to_retry)} endpoints")
                if len(to_retry) == 1:
                    print(f"Retrying: {to_retry[0]}")

                if single_result:
                    to_retry = str(to_retry[0])  # it's a URL object

                async for result in self.do_get(to_retry):
                    yield result
