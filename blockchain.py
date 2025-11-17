import hashlib

def append(*arrays: bytes) -> bytes:
    return b"".join(arrays)

def mine_block(prev_hash, quote, difficulty):
    nonce = 0
    quote_bytes = quote.encode("ascii")

    prefix = '0' * difficulty

    while True:
        length = (nonce.bit_length() + 7) // 8
        nonce_bytes = nonce.to_bytes(length, 'big')

        data = prev_hash + nonce_bytes + quote_bytes
        hash_bytes = hashlib.sha256(data).digest()

        bitstring = ''.join(f'{b:08b}' for b in hash_bytes)
        if bitstring.startswith(prefix):
            return nonce, hash_bytes
        nonce += 1

prev_block_hash = bytes.fromhex("0000007091d3cfe114ee307d23095b384fc90927eb7f496a5207114234470fa0")
quote = f"In OO, it's the data that is the \"important\" thing: you define the class which contains member data, and only incidentally contains code for manipulating the object. In FP, it's the code that's important: you define a function which contains code for working with the data, and only incidentally define what the data is. -- almkgor, on reddit"
nonce = 0
difficulty = 24
new_hash = None

nonce, new_hash = mine_block(prev_block_hash, quote, difficulty)

print(f"Nonce: {nonce}")
print(f"Hash: {new_hash.hex()}")