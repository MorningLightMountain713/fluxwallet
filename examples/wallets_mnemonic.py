# -*- coding: utf-8 -*-
#
#    fluxwallet - Python Cryptocurrency Library
#
#    EXAMPLES - Mnemonic Wallets
#
#    © 2018 February - 1200 Web Development <http://1200wd.com/>
#

import os

from fluxwallet.mnemonic import Mnemonic
from fluxwallet.wallets import BCL_DATABASE_DIR, Wallet

#
# Create Wallets
#

# First recreate database to avoid already exist errors
test_databasefile = os.path.join(BCL_DATABASE_DIR, "fluxwallet.test.sqlite")
test_database = "sqlite:///" + test_databasefile
if os.path.isfile(test_databasefile):
    os.remove(test_databasefile)

print("\n=== Create a simple Mnemonic wallet ===")
passphrase = Mnemonic().generate()
print("Your private key passphrase is:", passphrase)
password = input("Enter password to protect passphrase: ")
wlt = Wallet.create(
    "mnwlttest1",
    keys=passphrase,
    password=password,
    network="fluxwallet_test",
    db_uri=test_database,
)
wlt.get_key()
wlt.utxos_update()  # Create some test UTXOs
wlt.info()
to_key = wlt.get_key()
print("\n- Create transaction (send to own wallet)")
t = wlt.send_to(to_key.address, 50000000)
t.info()

print("\n- Successfully send, updated wallet info:")
wlt.info()
