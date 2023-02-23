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

import logging
from datetime import datetime

from fluxwallet.main import MAX_TRANSACTIONS
from fluxwallet.services.baseclient import BaseClient, ClientError

from fluxwallet.transactions import Transaction
import binascii

# from pprint import pprint
from rich.pretty import pprint

# from fluxwallet.transactions import Transaction

_logger = logging.getLogger(__name__)

PROVIDERNAME = "flux"
LIMIT_TX = 49


class FluxClient(BaseClient):
    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(
            network, PROVIDERNAME, base_url, denominator, *args
        )

    def load_tx(self, tx: dict):
        confirmations = tx.get("confirmations", 0)
        status = "unconfirmed"
        if confirmations:
            status = "confirmed"
        witness_type = "legacy"

        t = Transaction(
            locktime=tx["locktime"],
            version=tx["version"],
            network="flux",
            fee=tx["fees"],
            size=tx["size"],
            txid=tx["txid"],
            date=None if not confirmations else datetime.utcfromtimestamp(tx["time"]),
            confirmations=confirmations,
            block_height=tx["blockheight"],
            status=status,
            input_total=tx["valueIn"],
            coinbase=bool(tx["vin"]),
            output_total=tx["valueOut"],
            witness_type=witness_type,
        )
        index_n = 0
        if not tx["vin"]:
            # This is a coinbase transaction, add input
            t.add_input(prev_txid=b"\00" * 32, output_n=0, value=0)

        for ti in tx["vin"]:
            t.add_input(
                prev_txid=binascii.unhexlify(ti["txid"])[::-1],
                output_n=ti["vout"],
                unlocking_script=ti["scriptSig"]["hex"],
                index_n=index_n,
                value=ti["valueSat"],
                address=ti["addr"],
                sequence=ti["sequence"],
                strict=True,
            )
            index_n += 11
        for to in tx["vout"]:
            strict = True
            try:
                addr = to["scriptPubKey"]["addresses"][0]
            except KeyError:
                addr = ""
            try:
                t.add_output(
                    value=int(float(to["value"]) * 100000000),
                    address=addr,
                    lock_script=to["scriptPubKey"]["hex"],
                    spent=bool(to["spentTxId"]),
                    output_n=to["n"],
                    spending_txid=to["spentTxId"],
                    spending_index_n=to["spentIndex"],
                    strict=strict,
                )
            except Exception as e:
                print(repr(e))
                exit(0)
        return t

    def compose_request(
        self,
        category,
        data,
        cmd="",
        variables={},
        post_data=None,
        method="get",
        base=None,
    ):
        if data:
            data = "/" + data
        url_path = category + data
        if cmd != "":
            url_path += "/" + cmd

        try:
            data = self.request(
                url_path, variables, post_data=post_data, method=method, base=base
            )
        except Exception as e:
            print(e)
            print(repr(e))
            exit(0)
        return data

    def getutxos(self, address, after_txid="", limit=MAX_TRANSACTIONS):
        utxos = []
        skip = 0
        total = 1
        variables = {"address": address}
        res = self.compose_request("explorer", "utxo", variables=variables)
        print(res)
        for utxo in res["data"]:
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
                    "value": int(round(utxo["satoshis"], 0)),
                    "script": utxo["scriptPubKey"],
                }
            )
        return utxos[::-1][:limit]

    def estimatefee(self, blocks):
        return 3

    def blockcount(self):
        return self.compose_request("daemon", "getblockcount")["data"]

    def sendrawtransaction(self, rawtx):
        res = self.compose_request(
            "daemon",
            "sendrawtransaction",
            post_data={"hexstring": rawtx},
            method="post",
        )
        return {
            "txid": res["data"],
        }

    def gettransaction(self, txid):
        variables = {"txid": txid}
        # res = self.compose_request("daemon", "getrawtransaction", variables=variables)
        base = "https://explorer.runonflux.io/"
        res = self.compose_request("api/tx", txid, base=base)
        # pprint(res)
        # print("---")
        # raw = res["data"]
        # print("RAW")
        # pprint(raw)
        # tx = TransactionBuilder.parse(raw, network=self.network)
        # print("here is tx")
        # pprint(tx.as_dict())
        tx = self.load_tx(res)
        # pprint(tx.as_dict())
        return tx

    def gettransactions(self, address, after_txid, limit):
        variables = {"address": address}
        res = self.compose_request("explorer", "transactions", variables=variables)
        # {'status': 'success', 'data': []}
        # if status success
        txids = [tx["txid"] for tx in res["data"]][::-1]
        print("txids", txids)
        txs = []
        for txid in txids:
            tx = self.gettransaction(txid)
            txs.append(tx)
        return txs
