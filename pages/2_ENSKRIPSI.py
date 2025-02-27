import streamlit as st
import base64
import os
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter

if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    st.warning("🔒 Anda harus login terlebih dahulu!")
    st.stop()  # Menghentikan eksekusi halaman jika belum login

st.title("ENSKRIPSI")

st.sidebar.header("\U0001F510 Pengaturan Dekripsi")
metode = st.sidebar.selectbox("Pilih Metode Dekripsi", ["SISTEM XOR", "RC4", "DES", "AES"])

if metode in ["DES", "AES"]:
    mode = st.sidebar.selectbox("Pilih MODE", ["ECB", "CBC", "COUNTER"])
else:
    mode = None

st.write(f"Metode yang dipilih: **{metode}**")
if mode:
    st.write(f"Mode yang dipilih: **{mode}**")

def rc4_encrypt_decrypt(data, key):
    S = list(range(256))
    j = 0
    out = bytearray()
    key = [ord(c) for c in key]
    
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    
    return bytes(out)

#SISTEM XOR

if metode == "SISTEM XOR":
    st.subheader("\U0001F511 Enkripsi XOR")
    key = st.text_input("Masukkan Kunci Enkripsi", type="password")

    tab1, tab2 = st.tabs(["\U0001F524 Enkripsi Teks", "\U0001F4C2 Enkripsi File"])

    with tab1:
        plain_text = st.text_area("Masukkan Teks yang Akan Dienkripsi")
        if st.button("\U0001F510 Enkripsi Teks"):
            if key and plain_text:
                encrypted_text = base64.b64encode(
                    ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(plain_text)).encode()
                ).decode()
                st.success("Hasil Enkripsi:")
                st.code(encrypted_text, language="text")
            else:
                st.error("Mohon masukkan teks dan kunci enkripsi!")

    with tab2:
        uploaded_file = st.file_uploader("Unggah File untuk Enkripsi", 
                                         type=["xlsx", "csv", "txt", "json", "pdf", "jpg", "png", "gif", "mp4", "avi", "mov", "mkv"])
        if uploaded_file and key:
            file_data = uploaded_file.read()
            output_filename_enc = f"encrypted_{uploaded_file.name}"
            encrypted_data = bytes([byte ^ ord(key[i % len(key)]) for i, byte in enumerate(file_data)])
            if st.button("\U0001F510 Enkripsi File"):
                st.success(f"File {uploaded_file.name} berhasil dienkripsi!")
                st.download_button(
                    label="\U0001F4E5 Download File Terenkripsi",
                    data=encrypted_data,
                    file_name=output_filename_enc,
                    mime="application/octet-stream"
                )

#RC4

if metode == "RC4":
    st.subheader("\U0001F511 Enkripsi RC4")
    key = st.text_input("Masukkan Kunci Enkripsi", type="password")

    tab1, tab2 = st.tabs(["\U0001F524 Enkripsi Teks", "\U0001F4C2 Enkripsi File"])

    with tab1:
        plain_text = st.text_area("Masukkan Teks yang Akan Dienkripsi")
        if st.button("\U0001F510 Enkripsi Teks"):
            if key and plain_text:
                encrypted_text = base64.b64encode(rc4_encrypt_decrypt(plain_text.encode(), key)).decode()
                st.success("Hasil Enkripsi:")
                st.code(encrypted_text, language="text")
            else:
                st.error("Mohon masukkan teks dan kunci enkripsi!")

    with tab2:
        uploaded_file = st.file_uploader("Unggah File untuk Enkripsi", 
                                         type=["xlsx", "csv", "txt", "json", "pdf", "jpg", "png", "gif", "mp4", "avi", "mov", "mkv"])
        if uploaded_file and key:
            file_data = uploaded_file.read()
            output_filename_enc = f"encrypted_{uploaded_file.name}"
            encrypted_data = rc4_encrypt_decrypt(file_data, key)
            if st.button("\U0001F510 Enkripsi File"):
                st.success(f"File {uploaded_file.name} berhasil dienkripsi!")
                st.download_button(
                    label="\U0001F4E5 Download File Terenkripsi",
                    data=base64.b64encode(encrypted_data),
                    file_name=output_filename_enc,
                    mime="application/octet-stream"
                )
                

def generate_key(key: str):
    return key.encode().ljust(8, b'\0')[:8]

# DES
def encrypt_text(plain_text: str, key: str, mode: str):
    key_bytes = generate_key(key)
    
    if mode == "ECB":
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        encrypted_text = cipher.encrypt(pad(plain_text.encode(), DES.block_size))
    
    elif mode == "CBC":
        iv = os.urandom(8)
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        encrypted_text = iv + cipher.encrypt(pad(plain_text.encode(), DES.block_size))
    
    elif mode == "COUNTER":
        iv = os.urandom(8)
        ctr = Counter.new(64, initial_value=int.from_bytes(iv, byteorder="big"))
        cipher = DES.new(key_bytes, DES.MODE_CTR, counter=ctr)
        encrypted_text = iv + cipher.encrypt(plain_text.encode())
    
    return base64.b64encode(encrypted_text).decode()



def encrypt_file(input_file, key: str, mode: str):
    key_bytes = generate_key(key)
    file_data = input_file.read()

    if mode == "ECB":
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(file_data, DES.block_size))

    elif mode == "CBC":
        iv = os.urandom(8)
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(file_data, DES.block_size))

    elif mode == "COUNTER":
        iv = os.urandom(8)
        ctr = Counter.new(64, initial_value=int.from_bytes(iv, byteorder="big"))
        cipher = DES.new(key_bytes, DES.MODE_CTR, counter=ctr)
        encrypted_data = iv + cipher.encrypt(file_data)

    return encrypted_data


if metode == "DES":
    st.subheader("🔐 Enkripsi DES")
    key = st.text_input("Masukkan Kunci Enkripsi (8 karakter max)", max_chars=8)

    tab1, tab2 = st.tabs(["🔤 Enkripsi Teks", "📂 Enkripsi File"])

    with tab1:
        plain_text = st.text_area("Masukkan Teks yang Akan Dienkripsi")
        if st.button("🔐 Enkripsi Teks"):
            if key and plain_text:
                encrypted_text = encrypt_text(plain_text, key, mode)
                st.success("Hasil Enkripsi:")
                st.code(encrypted_text, language="text")
            else:
                st.error("Mohon masukkan teks dan kunci enkripsi!")

    with tab2:
        uploaded_file = st.file_uploader(
            "Unggah File untuk Enkripsi", 
            type=["txt", "pdf", "jpg", "png", "csv", "docx", "xlsx", "mp4", "mov", "avi"]
        )
        if uploaded_file and key:
            if st.button("🔐 Enkripsi File"):
                encrypted_data = encrypt_file(uploaded_file, key, mode)
                

                encrypted_file_name = uploaded_file.name
                st.success(f"File {uploaded_file.name} Berhasil Dienkripsi!")
                st.download_button("⬇️ Download File Terenkripsi", encrypted_data, encrypted_file_name)

# AES

def generate_key(key):
    return key.encode('utf-8').ljust(32, b'\0')


def encrypt_text(plain_text, key: str, mode: str):
    key_bytes = generate_key(key)

    if mode == "ECB":
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))

    elif mode == "CBC":
        iv = os.urandom(16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))

    elif mode == "COUNTER":
        iv = os.urandom(16)
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
        cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
        encrypted_data = iv + cipher.encrypt(plain_text.encode('utf-8'))

    return base64.b64encode(encrypted_data).decode('utf-8')


def encrypt_file(input_file, key, mode):
    key_bytes = generate_key(key)
    file_data = input_file.read()

    if mode == "ECB":
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        encrypted_data = cipher.encrypt(pad(file_data, AES.block_size))

    elif mode == "CBC":
        iv = get_random_bytes(16)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
        encrypted_data = iv + cipher.encrypt(pad(file_data, AES.block_size))

    elif mode == "COUNTER":
        iv = os.urandom(16)  # Buat IV acak
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
        cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
        encrypted_data = iv + cipher.encrypt(file_data) 

    return encrypted_data


if metode == "AES":
    st.subheader("🔐 Enkripsi AES")
    key = st.text_input("Masukkan Kunci (maks 32 karakter)", max_chars=32)

    tab1, tab2 = st.tabs(["🔤 Enkripsi Teks", "📂 Enkripsi File"])

    with tab1:
        plain_text = st.text_area("Masukkan Teks yang Akan Dienkripsi")
        if st.button("🔐 Enkripsi Teks"):
            if key and plain_text:
                encrypted_text = encrypt_text(plain_text, key, mode)
                st.success("Hasil Enkripsi (Base64):")
                st.code(encrypted_text, language="text")
            else:
                st.error("Mohon masukkan teks dan kunci enkripsi!")


    with tab2:
        uploaded_file = st.file_uploader("Unggah File untuk Enkripsi", type=[
            "txt", "pdf", "jpg", "png", "csv", "docx", "xlsx", "mp4", "mov", "avi"]
        )
        if uploaded_file and key:
            if st.button("🔐 Enkripsi File"):
                encrypted_data = encrypt_file(uploaded_file, key, mode)
                
                st.success(f"File {uploaded_file.name} Berhasil Dienkripsi!")
                st.download_button(
                "⬇️ Download File Terenkripsi", 
                encrypted_data, 
                uploaded_file.name
            )


if st.sidebar.button("❌ Logout"):
    st.session_state["authenticated"] = False
    st.rerun()
