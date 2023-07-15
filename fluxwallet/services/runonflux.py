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
from datetime import datetime
from decimal import Decimal

from collections.abc import Iterator
from contextlib import aclosing

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
        res: dict = await anext(self.do_get("daemon/getblockcount"))
        return res.get("data", 0)

    async def sendrawtransaction(self, rawtx: str) -> dict[str, dict]:
        # res = self.compose_request(
        #     "daemon/sendrawtransaction",
        #     post_data={"hexstring": rawtx},
        #     http_verb="post",
        # )
        res = await self.do_post(
            "daemon/sendrawtransaction", post_data={"hexstring": rawtx}
        )

        return {
            "txid": res["data"],
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
        txs: list[dict] = await self.do_get(
            "tx", base_url="https://explorer.runonflux.io/api/", targets=txids
        )
        # {'status': 404, 'url': '/api/tx/', 'error': 'Not found'}

        txs = sorted(txs, key=lambda x: x["blockheight"])
        tx_objects = [self.load_tx(tx) for tx in txs]

        return tx_objects

    async def get_transactions_by_address(
        self, address: str, after_tx_index: int = 0, limit: int = 0
    ) -> Iterator[list[FluxTransaction]]:
        # get lastest txid and count
        params = {"from": 0, "to": 1}

        after_txid_index = None
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

        txs: list[dict] = res.get("items", [])
        tx_count: int = res.get("totalItems", 0)

        if not txs:
            return

        if tx_count == 1:
            yield [self.load_tx(txs[0])]
            return

        # if after_txid:
        #     target_tx = next(filter(lambda x: x["txid"] == after_txid, txs), None)
        #     if target_tx:
        #         after_txid_index = txids.index(target_tx) + 1

        # from_tx = after_txid_index if after_txid_index else 0

        # this is always 0, newest
        from_tx = 0
        to_tx = (tx_count - after_tx_index) + 1

        tx_generator = self.do_get(
            paths=f"/api/addrs/{address}/txs",
            base_url="https://explorer.runonflux.io",
            pages=(from_tx, to_tx),
            chunksize=1,
        )

        # tx_generator = self.do_get(
        #     paths=["/api/txs"],
        #     base_url="https://explorer.runonflux.io",
        #     params=params,
        # )

        # total_count = 0
        async for batch in tx_generator:
            txs = []
            for result in batch:
                # total_count += len(result.get("txs", []))
                txs.extend(result.get("items"))
            yield [self.load_tx(tx) for tx in txs]

        # print("TOTAL COUNT", total_count)

        # target_blockheight = 0
        # if target_tx:
        #     target_blockheight = target_tx["blockheight"]

        # if target_blockheight:
        #     txs = list(
        #         filter(
        #             lambda x: x["blockheight"] >= target_blockheight
        #             and x["txid"] != after_txid,
        #             txs,
        #         )
        #     )
        #     txs = sorted(txs, key=lambda x: x["blockheight"])

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

        headers = {
            "User-Agent": f"fluxwallet/{FLUXWALLET_VERSION}",
            "Accept": "application/json",
        }
        transport = httpx.AsyncHTTPTransport(retries=5)

        async with httpx.AsyncClient(
            base_url=base_url, headers=headers, transport=transport
        ) as client:
            # this doesn't mix in the client options (have to build request)
            # req = httpx.Request(http_verb, uri)
            if not params:
                params = {}

            single_result = False
            if isinstance(paths, str):
                paths = [paths]
                single_result = True

            if pages:
                if isinstance(pages, int):
                    tasks = [
                        client.get(
                            paths[0],
                            params=params | {"pageNum": page},
                        )
                        # we already have the first page
                        for page in range(2, pages + 1)
                    ]
                else:  # tuple (from, to)
                    # fix if response to_x < response size, also missing last group
                    single_result = False
                    from_tx, to_tx = pages
                    response_size = 20

                    if to_tx < response_size:
                        ranges = [(0, 20)]
                    else:
                        to_tx = response_size * round(to_tx / response_size)

                        ranges = list(range(from_tx, to_tx + 1, response_size))
                        ranges = [*zip(ranges, ranges[1::])]

                    tasks = [
                        client.get(
                            paths[0], params=params | {"from": range[0], "to": range[1]}
                        )
                        for range in ranges
                    ]

            else:
                tasks = [client.get(path, params=params) for path in paths]

            results = []
            to_retry = []
            count = 0

            for coro in asyncio.as_completed(tasks):
                try:
                    result = await coro
                except httpx.RequestError as e:
                    print("REQUEST ERROR")
                    to_retry.append(e.request.url)
                else:
                    result = result.json()
                    if single_result:
                        print("yielding single!!!")
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
                async for result in self.do_get(to_retry):
                    yield result
