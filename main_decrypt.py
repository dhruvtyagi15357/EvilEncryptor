import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# The password used to generate the encryption key
password = b'\xc6\x93y\x97\xf9\xca\xe6H-C\xc6-\xb9F^\x89'


# The salt used to generate the encryption key
salt = base64.b64decode("v5zkedzsof9InVk0qDzlvg==")

# Generate the encryption key using the PBKDF2 (Password-Based Key Derivation Function 2) algorithm
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000
)
key = base64.urlsafe_b64encode(kdf.derive(password))

# Initialize the Fernet class with the encryption key
fernet = Fernet(key)

# Iterate through all the files in the current directory
for file in os.listdir():
    # Skip directories and non-encrypted files
    if not os.path.isfile(file) or not file.endswith(".encrypted"):
        continue

    # Read the contents of the encrypted file
    with open(file, "rb") as f:
        encrypted_data = f.read()

    # Decrypt the contents of the file
    data = fernet.decrypt(encrypted_data)

    # Write the decrypted data to a new file with the same name and without the ".encrypted" extension
    with open(file[:-10], "wb") as f:
        f.write(data)

    # Delete the encrypted file
    os.remove(file)

print("Files decrypted successfully")