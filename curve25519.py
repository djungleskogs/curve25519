import os
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

# Generate Alice's private and public keys
alice_private_key = x25519.X25519PrivateKey.generate()
alice_public_key = alice_private_key.public_key()

# Generate Bob's private and public keys
bob_private_key = x25519.X25519PrivateKey.generate()
bob_public_key = bob_private_key.public_key()

# Alice computes shared key (Alice's private key + Bob's public key)
shared_key_alice = alice_private_key.exchange(bob_public_key)

# Bob computes shared key (Bob's private key + Alice's public key)
shared_key_bob = bob_private_key.exchange(alice_public_key)

# Check if the shared keys match (If it is, a successful key exchange has occured)
assert shared_key_alice == shared_key_bob

# Use HKDF (derivative function) to derive a new symmetric key from the shared key
def derive_key(shared_key):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived key
        salt=None,
        info=b'Secret Message', 
    )
    return hkdf.derive(shared_key)

# Derive symmetric keys for Alice and Bob
symmetric_key_alice = derive_key(shared_key_alice)
symmetric_key_bob = derive_key(shared_key_bob)

# Encrypt and Decrypt a message from Alice to Bob
def encrypt_message(message, key):
    iv = os.urandom(16)  # Generate a random Initialization Vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    
    # Use PKCS7 padding and applying AES encryption 
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ct

def decrypt_message(ciphertext, key):
    iv = ciphertext[:16]  # Extract the IV from the ciphertext
    ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Use PKCS7 unpadding and applying AES encryption 
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message

# Message to be sent by Alice
message = b"Hello Bob! Please meet me @ Parkway Parade at 7pm SGT."

# Alice encrypts the message using the derived symmetric key and sends it to Bob
encrypted_message = encrypt_message(message, symmetric_key_alice)

# Bob decrypts the received message using the derived symmetric key
decrypted_message = decrypt_message(encrypted_message, symmetric_key_bob)

print("Original Message from Alice:", message.decode())
print("Decrypted Message by Bob:", decrypted_message.decode())
print("")
message = b"Understood, see you there!"
encrypted_message = encrypt_message(message, symmetric_key_bob)
decrypted_message = decrypt_message(encrypted_message, symmetric_key_alice)
print("Reply Message from Bob", message.decode())
print("Decrypted Message by Alice:", decrypted_message.decode())










