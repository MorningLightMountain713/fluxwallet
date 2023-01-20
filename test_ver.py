ver = b"\x01\x00\x00\x00"

header = int.from_bytes(ver, "little")

print(header & 0x7FFFFFFF)
print(header >> 31)
