This Python script I made demonstrates the use of the Curve25519 elliptic curve for key exchange and symmetric encryption. It provides 128 bits of security with a 256-bit key size, like NIST-P 256. Curve25519 is a Montgomery curve, using projective (X: Z) arithmetic with the Curve equation: y^2=x^3+486662x^2+x over the base field F_p  "with " p=2^255-19 and generator 9, projectivity (9:1). The Diffie-Hellman function is known as 'X25519' or 'Diffie-Hellman with Curve25519', while the underlying curve is called 'Curve25519'. Curve25519 is a state-of-the-art elliptic curve Diffie-Hellman function that is suitable for a wide variety of cryptographic applications. 

Overview

    Key Generation: The script generates private and public keys for both "Alice" and "Bob" using the Curve25519 algorithm.
    Key Exchange: "Alice" and "Bob" exchange their public keys and compute a shared secret key using the Diffie-Hellman key exchange protocol.
    Symmetric Encryption: The shared secret key is used to derive symmetric encryption keys using the HKDF (HMAC-based Key Derivation Function) algorithm.
    Encryption and Decryption: "Alice" encrypts a message using the derived key and sends it to "Bob". "Bob" decrypts the received ciphertext using the same key.

How to Use

    Run the provided Python script (curve25519_encryption.py) in a Python environment.
    The script will generate private and public keys for Alice and Bob, perform key exchange, and encrypt/decrypt a sample message.
    Review the console output to see the original message, encrypted message, and decrypted message.

