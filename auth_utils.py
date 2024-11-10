import os
import hashlib
from quantcrypt.internal.pqa.dss import FastSphincs, SmallSphincs
from quantcrypt.internal.pqa.errors import DSSSignFailedError, DSSVerifyFailedError

# Paths for saving keys
PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

def generate_signature(password):
    """
    Generates a signature for a given password.
    """
    # Salt and hash the password
    salt = os.urandom(16)  # Random salt
    password_hash = hashlib.sha256(salt + password.encode()).digest()

    # Initialize FastSphincs instance and generate keys
    fast_sphincs = FastSphincs()
    public_key, private_key = fast_sphincs.keygen()

    # Save private and public keys
    with open(PRIVATE_KEY_PATH, "wb") as private_file:
        private_file.write(private_key)
    with open(PUBLIC_KEY_PATH, "wb") as public_file:
        public_file.write(public_key)

    # Generate the signature
    try:
        signature = fast_sphincs.sign(private_key, password_hash)
    except DSSSignFailedError as e:
        print(f"Signature generation failed: {e}")
        return None, None, None
    
    return public_key, signature, salt  # Return salt for verification

def verify_signature(signature, password, salt):
    """
    Verifies the given signature against the password using the public key.
    """
    # Hash the password with the same salt as used during signature generation
    password_hash = hashlib.sha256(salt + password.encode()).digest()

    # Load the public key
    with open(PUBLIC_KEY_PATH, "rb") as public_file:
        public_key = public_file.read()

    fast_sphincs = FastSphincs()
    
    try:
        # Attempt to verify the signature
        is_valid = fast_sphincs.verify(public_key, password_hash, signature)
        return is_valid
    except DSSVerifyFailedError as e:
        print(f"Verification failed: {e}")
        return False
