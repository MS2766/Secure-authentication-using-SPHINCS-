import os
import hashlib
import subprocess

# Define the algorithm for OQS (LMS in this case)
OQS_ALGORITHM = "sphincsshake128fsimple"  # Example of SPHINCS+ algorithm

# Path to OpenSSL binary with oqs-provider enabled
OPENSSL_BIN_PATH = "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe"

def generate_signature(password):
    """
    Generates a signature for the given password using SPHINCS+ algorithm.
    """
    # Step 1: Ensure that the necessary files exist before proceeding
    if not os.path.exists("private_key.pem"):
        print("Error: private_key.pem not found.")
        return None, None
    if not os.path.exists("hashed_password.txt"):
        print("Error: hashed_password.txt not found.")
        return None, None

    # Generate a keypair using OQS (via OpenSSL with oqs-provider)
    # OpenSSL command to generate keypair using SPHINCS+
    print("Generating keypair...")
    result = os.system(f'"{OPENSSL_BIN_PATH}" genpkey -algorithm {OQS_ALGORITHM} -out private_key.pem')
    if result != 0:
        print("Error: OpenSSL failed to generate private_key.pem")
        return None, None

    result = os.system(f'"{OPENSSL_BIN_PATH}" pkey -in private_key.pem -pubout -out public_key.pem')
    if result != 0:
        print("Error: OpenSSL failed to generate public_key.pem")
        return None, None

    with open("private_key.pem", "r") as private_file:
        private_key = private_file.read()
    
    with open("public_key.pem", "r") as public_file:
        public_key = public_file.read()

    # Step 2: Salt and hash the password
    salt = os.urandom(16)
    password_hash = hashlib.sha256(salt + password.encode()).digest()

    # Save the hashed password to a file
    with open("hashed_password.txt", "wb") as hash_file:
        hash_file.write(password_hash)

    # Step 3: Sign the hashed password with the private key (use OpenSSL)
    print("Signing hashed password with private key...")
    result = subprocess.run(
        [OPENSSL_BIN_PATH, "dgst", "-sha256", "-sign", "private_key.pem", "-out", "signature.sig", "hashed_password.txt"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Error: OpenSSL command failed.")
        print("Standard Error Output:", result.stderr)
        return None, None

    # Step 4: Read the signature
    with open("signature.sig", "rb") as sig_file:
        signature = sig_file.read()

    return public_key, signature

def verify_signature(password, public_key):
    """
    Verifies the signature for the given password using SPHINCS+ algorithm.
    """
    # Salt and hash the password
    salt = os.urandom(16)
    password_hash = hashlib.sha256(salt + password.encode()).digest()

    # Save the hashed password to a file
    with open("hashed_password.txt", "wb") as hash_file:
        hash_file.write(password_hash)

    # OpenSSL command to verify the signature using the public key
    result = os.system(f'"{OPENSSL_BIN_PATH}" dgst -sha256 -verify public_key.pem -signature signature.sig hashed_password.txt')
    if result != 0:
        print("Error: Signature verification failed.")
        return False

    # Return result based on OpenSSL output (this part would typically require parsing)
    return True
