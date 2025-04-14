import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize session state variables
if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.key)

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'redirect_to_login' not in st.session_state:
    st.session_state.redirect_to_login = False

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    # First encrypt the text
    encrypted_text = st.session_state.cipher.encrypt(text.encode()).decode()
    
    # Generate a unique data ID (using the encrypted text itself)
    data_id = f"data_{len(st.session_state.stored_data) + 1}"
    
    # Store the data with hashed passkey
    hashed_passkey = hash_passkey(passkey)
    st.session_state.stored_data[data_id] = {
        "encrypted_text": encrypted_text, 
        "passkey": hashed_passkey
    }
    
    return data_id, encrypted_text

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    
    # Check if the data exists with the provided passkey
    for data_id, data in st.session_state.stored_data.items():
        if data["encrypted_text"] == encrypted_text and data["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0  # Reset failed attempts on success
            return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
    
    # Increment failed attempts if no match found
    st.session_state.failed_attempts += 1
    
    # Check if max attempts reached
    if st.session_state.failed_attempts >= 3:
        st.session_state.redirect_to_login = True
    
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Handle redirect to login if necessary
if st.session_state.redirect_to_login:
    st.session_state.redirect_to_login = False
    choice = "Login"
else:
    # Navigation sidebar
    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.sidebar.selectbox("Navigation", menu)

# Main content based on navigation choice
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    
    # Add some information about the system
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
    
    # Show current storage statistics
    st.info(f"Currently storing {len(st.session_state.stored_data)} encrypted data entries")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    
    # Create form for data input
    user_data = st.text_area("Enter Data:", height=200)
    passkey = st.text_input("Enter Passkey:", type="password")
    
    # Button to encrypt and save
    if st.button("Encrypt & Save"):
        if user_data and passkey:
            data_id, encrypted_text = encrypt_data(user_data, passkey)
            
            # Show success message with data ID
            st.success(f"✅ Data stored securely with ID: {data_id}")
            
            # Display the encrypted text
            with st.expander("View Encrypted Data"):
                st.code(encrypted_text)
                st.warning("⚠️ Keep your Data ID and passkey safe! You'll need them to retrieve your data.")
        else:
            st.error("⚠️ Both data and passkey are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    # Display the current attempt status
    if st.session_state.failed_attempts > 0:
        st.warning(f"Failed attempts: {st.session_state.failed_attempts}/3")
    
    # Create tabs for different retrieval methods
    tab1, tab2 = st.tabs(["Retrieve by ID", "Retrieve by Encrypted Text"])
    
    with tab1:
        # Option to retrieve by data ID
        data_id = st.text_input("Enter Data ID:")
        passkey1 = st.text_input("Enter Passkey:", type="password", key="passkey1")
        
        # Show available IDs for demonstration purposes
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
                        
                        # Check if max attempts reached
                        if st.session_state.failed_attempts >= 3:
                            st.error("🔒 Too many failed attempts! Redirecting to Login Page.")
                            st.session_state.redirect_to_login = True
                            st.experimental_rerun()
                else:
                    st.error("❌ Data ID not found!")
            else:
                st.error("⚠️ Both Data ID and passkey are required!")
    
    with tab2:
        # Option to retrieve by pasting encrypted text
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
                    
                    # Check if max attempts reached
                    if st.session_state.failed_attempts >= 3:
                        st.error("🔒 Too many failed attempts! Redirecting to Login Page.")
                        st.session_state.redirect_to_login = True
                        st.experimental_rerun()
            else:
                st.error("⚠️ Both encrypted text and passkey are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    
    # Create login form
    login_pass = st.text_input("Enter Master Password:", type="password")
    
    if st.button("Login"):
        # In a real app, this would use a more secure authentication mechanism
        if login_pass == "admin123":
            # Reset failed attempts counter
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully!")
            
            # Add button to go to Retrieve Data
            if st.button("Go to Retrieve Data"):
                choice = "Retrieve Data"
                st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")

# Add a footer
st.markdown("---")
st.markdown("""
<div style="text-align: center">
    <small>🛡️ Secure Data Encryption System | Python Assignment</small>
</div>
""", unsafe_allow_html=True)