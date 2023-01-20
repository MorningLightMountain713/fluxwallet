from fluxwallet.mnemonic import Mnemonic
from fluxwallet.wallets import Wallet, wallet_delete

passphrase = Mnemonic().generate()
print(passphrase)
