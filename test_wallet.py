from fluxwallet.mnemonic import Mnemonic
from fluxwallet.wallets import Wallet, wallet_delete

passphrase = Mnemonic().generate()
print(passphrase)
w = Wallet.create("gravywallet", keys=passphrase, network="flux")
w.get_key()
w.info()
