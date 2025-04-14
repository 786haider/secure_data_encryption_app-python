import streamlit as st
import hashlib
from cryptography.fernet import Fernet

if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.key)

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {} 

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'redirect_to_login' not in st.session_state:
    st.session_state.redirect_to_login = False

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    encrypted_text = st.session_state.cipher.encrypt(text.encode()).decode()
    
    data_id = f"data_{len(st.session_state.stored_data) + 1}"

    hashed_passkey = hash_passkey(passkey)
    st.session_state.stored_data[data_id] = {
        "encrypted_text": encrypted_text, 
        "passkey": hashed_passkey
    }
    
    return data_id, encrypted_text
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    
    for data_id, data in st.session_state.stored_data.items():
        if data["encrypted_text"] == encrypted_text and data["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0 
            return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1

    if st.session_state.failed_attempts >= 3:
        st.session_state.redirect_to_login = True
    
    return None

st.set_page_config("🔒 Secure Data System Of Haider",layout="wide")
st.title("🔒 Secure Data Encryption System")

if st.session_state.redirect_to_login:
    st.session_state.redirect_to_login = False
    choice = "Login"
else:
    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.sidebar.selectbox("Navigation", menu)
    st.sidebar.write("---")
    st.sidebar.write("👨‍💻 About Developer")
    st.sidebar.markdown("""
        #### 👨‍💻 **Haider Hussain**
        - 💻 [GitHub](https://github.com/786haider/secure_data_encryption_app-python)
        """)
    st.sidebar.write("🔑 Master Password: `admin123`")
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

    st.markdown("""
    ### How it works:
    
    1. **Store Data**: Enter your sensitive information and a passkey to encrypt it
    2. **Retrieve Data**: Use your passkey to decrypt and view your data
    3. **Security**: All data is encrypted and can only be accessed with the correct passkey
    
    ### Security Features:
    
    - Strong encryption using Fernet (symmetric encryption)
    - Passkeys are hashed using SHA-256
    - Three attempts limit before requiring reauthorization
    - In-memory storage with no external database
    """)
    
    
    st.info(f"Currently storing {len(st.session_state.stored_data)} encrypted data entries")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    
   
    user_data = st.text_area("Enter Data:", height=200)
    passkey = st.text_input("Enter Passkey:", type="password")
    
    if st.button("Encrypt & Save"):
        if user_data and passkey:
            data_id, encrypted_text = encrypt_data(user_data, passkey)

            st.success(f"✅ Data stored securely with ID: {data_id}")

            with st.expander("View Encrypted Data"):
                st.code(encrypted_text)
                st.warning("⚠️ Keep your Data ID and passkey safe! You'll need them to retrieve your data.")
        else:
            st.error("⚠️ Both data and passkey are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")

    if st.session_state.failed_attempts > 0:
        st.warning(f"Failed attempts: {st.session_state.failed_attempts}/3")

    tab1, tab2 = st.tabs(["Retrieve by ID", "Retrieve by Encrypted Text"])
    
    with tab1:
        data_id = st.text_input("Enter Data ID:")
        passkey1 = st.text_input("Enter Passkey:", type="password", key="passkey1")
        if st.session_state.stored_data:
            st.info(f"Available IDs: {', '.join(st.session_state.stored_data.keys())}")
        
        if st.button("Decrypt by ID"):
            if data_id and passkey1:
                if data_id in st.session_state.stored_data:
                    encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                    decrypted_text = decrypt_data(encrypted_text, passkey1)
                    
                    if decrypted_text:
                        st.success("✅ Data decrypted successfully!")
                        st.text_area("Decrypted Data:", value=decrypted_text, height=150, key="decrypted1")
                    else:
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                        if st.session_state.failed_attempts >= 3:
                            st.error("🔒 Too many failed attempts! Redirecting to Login Page.")
                            st.session_state.redirect_to_login = True
                            st.experimental_rerun()
                else:
                    st.error("❌ Data ID not found!")
            else:
                st.error("⚠️ Both Data ID and passkey are required!")
    
    with tab2:
        encrypted_text = st.text_area("Enter Encrypted Text:")
        passkey2 = st.text_input("Enter Passkey:", type="password", key="passkey2")
        
        if st.button("Decrypt Text"):
            if encrypted_text and passkey2:
                decrypted_text = decrypt_data(encrypted_text, passkey2)
                
                if decrypted_text:
                    st.success("✅ Data decrypted successfully!")
                    st.text_area("Decrypted Data:", value=decrypted_text, height=150, key="decrypted2")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                    if st.session_state.failed_attempts >= 3:
                        st.error("🔒 Too many failed attempts! Redirecting to Login Page.")
                        st.session_state.redirect_to_login = True
                        st.experimental_rerun()
            else:
                st.error("⚠️ Both encrypted text and passkey are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")
    
    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully!")
            if st.button("Go to Retrieve Data"):
                choice = "Retrieve Data"
                st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
st.markdown("---")
st.markdown("""
<div style="text-align: center">
    <small>🛡️ Secure Data Encryption System | Python Assignment</small>
</div>
""", unsafe_allow_html=True)