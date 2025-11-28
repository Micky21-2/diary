import streamlit as st
import json
import os
import base64
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import SHA256  
from Crypto.Random import get_random_bytes 

DIARY_FILE = "diary_store.json"
KEY_SIZE = 16  


def get_key_from_password(password):
    h = SHA256.new()
    h.update(password.encode('utf-8'))
    return h.digest()[:KEY_SIZE]

def encrypt_entry(entry_text, password):
    key = get_key_from_password(password)
    data = entry_text.encode('utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext, tag, nonce

def decrypt_entry(ciphertext, tag, nonce, password):
    key = get_key_from_password(password)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data.decode('utf-8')
    except ValueError:
        raise ValueError("Decryption failed: Wrong password or tampered data")

def load_entries():
    if not os.path.exists(DIARY_FILE):
        return []
    try:
        if os.path.getsize(DIARY_FILE) == 0:
            return []
        with open(DIARY_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []

def save_all_entries(entries):
    with open(DIARY_FILE, 'w') as f:
        json.dump(entries, f, indent=2)

def page_add_entry():
    st.header("✒️ Write a New Entry")
    
    with st.form(key="add_entry_form", clear_on_submit=True):
        title = st.text_input("Entry Title:")
        entry_text = st.text_area("What's on your mind?", height=200)
        password = st.text_input("Password to lock this entry:", type="password")
        submitted = st.form_submit_button("Save Entry")

    if submitted:
        if not title:
            st.warning("Please enter a title.")
        elif not entry_text:
            st.warning("Please type an entry.")
        elif not password:
            st.warning("Please enter a password.")
        else:
            try:
                ciphertext, tag, nonce = encrypt_entry(entry_text, password)
                new_entry = {
                    "title": title,
                    "timestamp": datetime.now().isoformat(),
                    "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                    "tag": base64.b64encode(tag).decode('utf-8'),
                    "nonce": base64.b64encode(nonce).decode('utf-8')
                }
                
                entries = load_entries()
                entries.append(new_entry)
                save_all_entries(entries)
                
                st.toast("Entry locked and saved successfully!", icon="✅")
                
            except Exception as e:
                st.error(f"An error occurred during encryption: {e}")

def page_view_entries():
    st.header("📖 Read Your Diary")
    entries = load_entries()
    
    if not entries:
        st.info("Your diary is empty. Add an entry first!")
        return

    entry_labels = [
        f"{data.get('title', 'Untitled')} (Saved: {data.get('timestamp', 'Unknown time')})" 
        for i, data in enumerate(entries)
    ]
    selected_label = st.selectbox("Choose an entry to read:", entry_labels)
    
    if not selected_label:
        return

    choice_index = entry_labels.index(selected_label)
    entry_data = entries[choice_index]
    
    password = st.text_input(f"Password for '{entry_data.get('title', 'Untitled')}':", type="password", key=f"view_pass_{choice_index}")
    
    if st.button("Unlock and Read", key=f"view_btn_{choice_index}"):
        if not password:
            st.warning("Please enter the password.")
        else:
            try:
                ciphertext = base64.b64decode(entry_data["ciphertext"])
                tag = base64.b64decode(entry_data["tag"])
                nonce = base64.b64decode(entry_data["nonce"])
                
                plaintext = decrypt_entry(ciphertext, tag, nonce, password)
                
                st.text_area("Decrypted Entry:", plaintext, height=200, disabled=True, key=f"view_text_{choice_index}")
            except Exception:
                st.error("Decryption failed. Wrong password or corrupt data.")

def page_delete_entry():
    st.header("🗑️ Delete an Entry")
    entries = load_entries()
    
    if not entries:
        st.info("No entries to delete.")
        return

    entry_labels = [
        f"{data.get('title', 'Untitled')} (Saved: {data.get('timestamp', 'Unknown time')})" 
        for i, data in enumerate(entries)
    ]
    selected_label = st.selectbox("Choose an entry to DELETE:", entry_labels, key="delete_select")
    
    if not selected_label:
        return
        
    choice_index = entry_labels.index(selected_label)
    entry_data = entries[choice_index]
    
    st.warning(f"You are about to delete the entry: **{entry_data.get('title', 'Untitled')}**")
    password = st.text_input(f"Password to CONFIRM deletion:", type="password", key=f"delete_pass_{choice_index}")
    
    if st.button("Permanently Delete Entry", type="primary", key=f"delete_btn_{choice_index}"):
        if not password:
            st.warning("Please enter the password to confirm.")
        else:
            try:
                ciphertext = base64.b64decode(entry_data["ciphertext"])
                tag = base64.b64decode(entry_data["tag"])
                nonce = base64.b64decode(entry_data["nonce"])

                decrypt_entry(ciphertext, tag, nonce, password)
                
                entries.pop(choice_index)
                save_all_entries(entries)
                
                st.success(f"✅ Entry '{entry_data.get('title', 'Untitled')}' was successfully deleted.")
                st.rerun() 
            except Exception:
                st.error("Wrong password or Corrupt Data. Deletion cancelled.")


def main():
    st.set_page_config(
        page_title="My Private Diary",
        page_icon="📓",
        layout="centered"
    )

    st.markdown("""
    <style>
    /* Import serif font */
    @import url('https://fonts.googleapis.com/css2?family=Merriweather:wght@300;400;700&display=swap');
    
    html, body, [class*="st-"], [class*="css-"] {
        font-family: 'Merriweather', 'Georgia', serif;
    }

    /* Main app background */
    .stApp {
        background-color: #121212; /* Very Dark (Black) */
    }

    /* All text */
    h1, h2, h3, h4, h5, h6, p, label, .st-bv, .st-cx {
        color: #FFFFFF; /* White Text */
    }
    
    /* Title */
    h1 {
        color: #FFFFFF; /* White */
    }

    /* Caption text */
    .stCaption {
        color: #AAAAAA; /* Light Gray */
    }

    /* Tab container background */
    [data-testid="stTabs"] {
        background-color: #1E1E1E; /* Dark Gray */
    }
    
    /* Active tab */
    [data-testid="stTabs"] button[aria-selected="true"] {
        background-color: #333333; /* Darker Gray */
        color: #FFFFFF; /* White Text */
    }
    
    /* Inactive tab */
    [data-testid="stTabs"] button {
        color: #AAAAAA; /* Light Gray Text */
    }

    /* Form background */
    [data-testid="stForm"] {
        background-color: #1E1E1E; /* Dark Gray */
        border: 1px solid #555555; /* Gray border */
        border-radius: 10px;
        padding: 20px;
    }

    /* --- REFINED BUTTONS --- */

    /* Main "Save" / "Unlock" button (Outline Style) */
    .stButton > button {
        border-radius: 5px;
        border: 2px solid #FFFFFF; /* White Border */
        background-color: transparent; /* Transparent Background */
        color: #FFFFFF; /* White Text */
        transition: all 0.2s ease-in-out; /* Smooth transition */
    }
    .stButton > button:hover {
        background-color: #FFFFFF; /* White Fill */
        color: #121212; /* Black Text */
        border: 2px solid #FFFFFF;
    }
    
    /* "Delete" button (Primary) - Solid Gray, Red on Hover */
    .stButton > button[kind="primary"] {
        border-radius: 5px;
        border: 2px solid #555555; /* Gray Border */
        background-color: #333333; /* Dark Gray Fill */
        color: #FAFAFA; /* White Text */
        transition: all 0.2s ease-in-out; /* Smooth transition */
    }
    .stButton > button[kind="primary"]:hover {
        background-color: #D32F2F; /* Red Fill on Hover */
        color: #FFFFFF; /* White Text */
        border: 2px solid #D32F2F; /* Red Border on Hover */
    }
    
    /* --- END REFINED BUTTONS --- */
    
    /* Text Input & Text Area */
    .stTextInput input, .stTextArea textarea, .stSelectbox > div {
        background-color: #333333; /* Dark Gray Input */
        border: 1px solid #555555; /* Gray Border */
        color: white; /* Light Text */
    }
    .stSelectbox > div {
        border: none; /* Selectbox is special */
    }

    /* Success/Error/Warning boxes */
    [data-testid="stAlert"] {
        border: 1px solid;
    }
    
    [data-testid="stSuccess"] {
        color: #12121s; /* Black text for light green box */
    }
    
    /* Toasts (notifications) */
    [data-testid="stToast"] {
        background-color: #333333;
        border: 1px solid #FFFFFF;
        color: #FFFFFF;
    }

    </style>
    """, unsafe_allow_html=True)

    st.title("📓 My Private Diary")
    st.caption("Locked with AES Encryption & SHA-256")

    tab_add, tab_view, tab_delete = st.tabs([
        "✒️ New Entry", 
        "📖 Read Diary", 
        "🗑️ Delete Entry", 
    ])

    with tab_add:
        page_add_entry()

    with tab_view:
        page_view_entries()

    with tab_delete:
        page_delete_entry()


if __name__ == "__main__":
    main()