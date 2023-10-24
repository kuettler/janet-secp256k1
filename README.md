# secp256k1

Binding to the secp256k1 functions.

## Usage

This package supports signing and verifying hashes via a key pair.

```
(import jsecp256k1)

# 1. Pick a 32 byte string as a secret key.
(def seckey "01234567890123456789012345678901")

# 2. Verify the secret is valid
(assert (jsecp256k1/ec-seckey-verify seckey))

# 3. Extract the corresponding public key
(def public-key (jsecp256k1/ec-pubkey-create seckey))

# 4. Create a 32 byte hash value of the document to sign
(def msghash32 "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")

# 5. Create the signature using the secret key
(def sig (jsecp256k1/ec-ecdsa-sign msghash32 seckey))

# 6. Verify the signature using the public key
(assert (jsecp256k1/ecdsa-verify sig msghash32 public-key))

```
