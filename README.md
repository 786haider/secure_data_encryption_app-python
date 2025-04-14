# secure_data_encryption_app-python
<p>
Core Features Implemented

Data Storage (In-Memory Dictionary)

Uses Streamlit's session state to maintain data in memory
Stores encrypted text and hashed passkeys
Creates unique IDs for each data entry


Secure Encryption & Decryption

Implements Fernet encryption from the cryptography library
Securely hashes passkeys with SHA-256
Only allows decryption with the correct passkey


Authentication & Security

Tracks failed decryption attempts
Limits to three attempts before requiring reauthorization
Redirects to login page when attempt limit is reached
Clearly displays remaining attempts


User Interface

Clean and intuitive Streamlit interface
Navigation sidebar with different sections
Home page with system overview
Store Data page with form for encrypting data
Retrieve Data page with two options (by ID or by encrypted text)
Login page for reauthorization

Deploy url:
 # https://secure-data-encryptionapp-python-haider-neezpfbmcavhwwsgyonzrn.streamlit.app/
 


How to Use the System

Store Data:

Navigate to the "Store Data" page
Enter your sensitive data and create a passkey
Click "Encrypt & Save"
The system provides a data ID and shows the encrypted text


Retrieve Data:

Navigate to the "Retrieve Data" page
Either use the data ID or paste the encrypted text
Enter the correct passkey
View your decrypted data


Login/Reauthorization:

If you fail three decryption attempts, you'll be redirected to the login page
Enter the master password (admin123) to regain access
Return to the Retrieve Data page to try again



Security Considerations

All passkeys are hashed using SHA-256 before storage
Data is encrypted using Fernet symmetric encryption
The system enforces a three-attempt limit to prevent brute force attacks
The master password provides an additional layer of security
</p>