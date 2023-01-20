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

from fluxwallet.transactions.transaction import TransactionBuilder
from pprint import pprint

# from fluxwallet.transactions import Transaction

_logger = logging.getLogger(__name__)

PROVIDERNAME = "flux"
LIMIT_TX = 49


class FluxClient(BaseClient):
    def __init__(self, network, base_url, denominator, *args):
        super(self.__class__, self).__init__(
            network, PROVIDERNAME, base_url, denominator, *args
        )

    def compose_request(
        self, category, data, cmd="", variables={}, post_data=None, method="get"
    ):
        if data:
            data = "/" + data
        url_path = category + data
        if cmd != "":
            url_path += "/" + cmd

        try:
            data = self.request(url_path, variables, post_data=post_data, method=method)
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
            # need to go look up the tx to get the confirmations etc etc.
            utxos.append(
                {
                    "address": utxo["address"],
                    "txid": utxo["txid"],
                    # "confirmations": utxo["confirmations"],
                    "confirmations": 0,
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
        res = self.compose_request("daemon", "getrawtransaction", variables=variables)
        raw = res["data"]
        tx = TransactionBuilder.parse(raw, network=self.network)
        print("here is tx")
        pprint(tx.as_dict())
        return tx

    def gettransactions(self, address, after_txid, limit):
        variables = {"address": address}
        res = self.compose_request("explorer", "transactions", variables=variables)
        # {'status': 'success', 'data': []}
        # if status success
        txids = [tx["txid"] for tx in res["data"]]
        txs = []
        for txid in txids:
            tx = self.gettransaction(txid)
            txs.append(tx)
        return txs
