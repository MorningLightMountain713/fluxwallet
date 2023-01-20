from fluxwallet.transactions.errors import TransactionError


def get_unlocking_script_type(
    locking_script_type, witness_type="legacy", multisig=False
):
    """
    Specify locking script type and get corresponding script type for unlocking script

    >>> get_unlocking_script_type('p2wsh')
    'p2sh_multisig'

    :param locking_script_type: Locking script type. I.e.: p2pkh, p2sh, p2wpkh, p2wsh
    :type locking_script_type: str
    :param witness_type: Type of witness: legacy or segwit. Default is legacy
    :type witness_type: str
    :param multisig: Is multisig script or not? Default is False
    :type multisig: bool

    :return str: Unlocking script type such as sig_pubkey or p2sh_multisig
    """

    if locking_script_type in ["p2pkh", "p2wpkh"]:
        return "sig_pubkey"
    elif locking_script_type == "p2wsh" or (witness_type == "legacy" and multisig):
        return "p2sh_multisig"
    elif locking_script_type == "p2sh":
        if not multisig:
            return "sig_pubkey"
        else:
            return "p2sh_multisig"
    elif locking_script_type == "p2pk":
        return "signature"
    else:
        raise TransactionError("Unknown locking script type %s" % locking_script_type)


def transaction_update_spents(txs, address):
    """
    Update spent information for list of transactions for a specific address. This method assumes the list of
    transaction complete and up-to-date.

    This method loops through all the transaction and update all transaction outputs for given address, checks
    if the output is spent and add the spending transaction ID and index number to the outputs.

    The same list of transactions with updates outputs will be returned

    :param txs: Complete list of transactions for given address
    :type txs: list of Transaction
    :param address: Address string
    :type address: str

    :return list of Transaction:
    """
    spend_list = {}
    for t in txs:
        for inp in t.inputs:
            if inp.address == address:
                spend_list.update({(inp.prev_txid.hex(), inp.output_n_int): t})
    address_inputs = list(spend_list.keys())
    for t in txs:
        for to in t.outputs:
            if to.address != address:
                continue
            spent = True if (t.txid, to.output_n) in address_inputs else False
            txs[txs.index(t)].outputs[to.output_n].spent = spent
            if spent:
                spending_tx = spend_list[(t.txid, to.output_n)]
                spending_index_n = [
                    inp
                    for inp in txs[txs.index(spending_tx)].inputs
                    if inp.prev_txid.hex() == t.txid and inp.output_n_int == to.output_n
                ][0].index_n
                txs[txs.index(t)].outputs[to.output_n].spending_txid = spending_tx.txid
                txs[txs.index(t)].outputs[
                    to.output_n
                ].spending_index_n = spending_index_n
    return txs
