import streamlit as st
import hashlib
import base64
import json
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Initialize session state variables if they don't exist
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'locked_until' not in st.session_state:
    st.session_state.locked_until = 0

# Salt for key derivation (in production this should be stored securely)
SALT = b'secure_salt_value_for_key_derivation'

# Function to derive a key from the passkey
def derive_key(passkey):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    key = derive_key(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    try:
        key = derive_key(passkey)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Check if system is locked due to too many failed attempts
current_time = time.time()
if st.session_state.locked_until > current_time:
    st.error(f"🔒 System locked due to too many failed attempts. Try again in {int(st.session_state.locked_until - current_time)} seconds")
    choice = "Login"

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    st.info("""
    ### How it works:
    1. Go to **Store Data** to encrypt and save your sensitive information
    2. Use a strong, unique passkey for each data entry
    3. Your data is encrypted with advanced algorithms and stored securely
    4. Go to **Retrieve Data** when you need to access your information
    5. You'll need to provide the correct passkey to decrypt your data
    
    ### Security Features:
    - Data is encrypted with Fernet symmetric encryption
    - Passkeys are hashed using SHA-256
    - Three failed attempts will lock you out and require reauthorization
    """)

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    
    user_data = st.text_area("Enter Data to Encrypt:", height=150)
    data_label = st.text_input("Give this data entry a label:")
    passkey = st.text_input("Create a Passkey:", type="password")
    passkey_confirm = st.text_input("Confirm Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey and data_label:
            if passkey != passkey_confirm:
                st.error("⚠️ Passkeys do not match!")
            else:
                # Encrypt the data with the passkey
                encrypted_text = encrypt_data(user_data, passkey)
                
                # Store the encrypted data and hashed passkey
                hashed_passkey = hash_passkey(passkey)
                st.session_state.stored_data[data_label] = {
                    "encrypted_text": encrypted_text, 
                    "passkey": hashed_passkey
                }
                
                st.success("✅ Data stored securely!")
                
                # Display the encrypted text (users would need this to retrieve later)
                st.code(encrypted_text, language="text")
                st.info("💡 Keep your passkey safe! You'll need it to decrypt this data.")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    # Show available data labels if any exist
    if st.session_state.stored_data:
        options = list(st.session_state.stored_data.keys())
        selected_label = st.selectbox("Select a data entry to decrypt:", options)
        encrypted_text = st.session_state.stored_data[selected_label]["encrypted_text"]
        
        # Display encrypted text but allow manual entry too
        st.text_area("Encrypted Data:", value=encrypted_text, height=100, disabled=True)
    else:
        st.info("No data entries found. Go to 'Store Data' to create one.")
        encrypted_text = st.text_area("Or enter encrypted data manually:", height=100)
    
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            # First try direct decryption
            decrypted_text = decrypt_data(encrypted_text, passkey)
            
            if decrypted_text:
                st.success("✅ Decryption successful!")
                st.text_area("Decrypted Data:", value=decrypted_text, height=150)
                # Reset failed attempts on success
                st.session_state.failed_attempts = 0
            else:
                # Increment failed attempts
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                
                if remaining > 0:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                else:
                    # Lock the system for 30 seconds
                    st.session_state.locked_until = time.time() + 30
                    st.error("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Both encrypted data and passkey are required!")

elif choice == "Login" :
 if choice == "Signup":
    st.subheader("🔑 Reauthorization Required")
    
    if st.session_state.locked_until > time.time():
        lock_time = int(st.session_state.locked_until - time.time())
        st.warning(f"🕒 System locked for {lock_time} more seconds due to too many failed attempts.")
       
    login_pass = st.text_input("Enter Master Password:", type="password")
    if st.button("Signup"):
        st.session_state.stored_data = {}
        password = st.text_input("Create Master Password:", type="password")
        confirm_password = st.text_input("Confirm Master Password:", type="password")
        if password == confirm_password:
            st.session_state.master_password = password
            st.success("✅ Signup successful! Redirecting to Home...")
            time.sleep(1)  # Short delay for user feedback
            st.experimental_rerun()
        else:
          st.button("Login")
        
        if login_pass == password:
            st.session_state.failed_attempts = 0
            st.session_state.locked_until = 0
            st.success("✅ Reauthorized successfully! Redirecting to Home...")
            time.sleep(1)  # Short delay for user feedback
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")

# Display current system status in sidebar
st.sidebar.subheader("System Status")
st.sidebar.info(f"📊 Data entries: {len(st.session_state.stored_data)}")
st.sidebar.info(f"🔑 Failed attempts: {st.session_state.failed_attempts}/3")

if st.session_state.locked_until > time.time():
    st.sidebar.error("🔒 System locked")
else:
    st.sidebar.success("✅ System unlocked")