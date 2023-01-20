from fluxwallet.wallets import wallet_create_or_open
from fluxwallet.mnemonic import Mnemonic

mnemonic = Mnemonic().generate()
print(mnemonic)

w = wallet_create_or_open("FluxWallet", keys=mnemonic, network="flux")

key = w.get_key()
print(key.__dict__)

# print(key.address)
