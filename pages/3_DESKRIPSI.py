import os
import base64
from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
import streamlit as st

if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    st.warning("🔒 Anda harus login terlebih dahulu!")
    st.stop()  


st.title("DESKRIPSI")

st.sidebar.header("🔐 Pengaturan Dekripsi")
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
    st.subheader("🔑 Dekripsi XOR")
    key = st.text_input("Masukkan Kunci Dekripsi", type="password")
    tab1, tab2 = st.tabs(["🔤 Dekripsi Teks", "📂 Dekripsi File"])

    with tab1:
        encrypted_text_input = st.text_area("Masukkan Teks Terenkripsi")
        if st.button("🔓 Dekripsi Teks"):
            if key and encrypted_text_input:
                try:
                    decrypted_text = ''.join(
                        chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(base64.b64decode(encrypted_text_input).decode())
                    )
                    st.success("Hasil Dekripsi:")
                    st.code(decrypted_text, language="text")
                except Exception:
                    st.error("Kesalahan dalam proses dekripsi. Periksa kembali teks dan kunci!")

    with tab2:
        uploaded_file = st.file_uploader("Unggah File untuk Dekripsi", type=["xlsx", "csv", "txt", "json", "pdf", "jpg", "jpeg", "png", "gif", "mp4", "avi", "mov", "mkv"])
        if uploaded_file and key:
            file_data = uploaded_file.read()
            output_filename_dec = f"decrypted_{uploaded_file.name}"
            decrypted_data = bytes([byte ^ ord(key[i % len(key)]) for i, byte in enumerate(file_data)])
            if st.button("🔓 Dekripsi File"):
                st.success(f"File {uploaded_file.name} berhasil didekripsi!")
                st.download_button(
                    label="📥 Download File Didekripsi",
                    data=decrypted_data,
                    file_name=output_filename_dec,
                    mime="application/octet-stream"
                )

#SISTEMRC4

elif metode == "RC4":
    st.subheader("🔑 Dekripsi RC4")
    key = st.text_input("Masukkan Kunci Dekripsi", type="password")

    tab1, tab2 = st.tabs(["🔤 Dekripsi Teks", "📂 Dekripsi File"])


    with tab1:
        encrypted_text_input = st.text_area("Masukkan Teks Terenkripsi")
        if st.button("🔓 Dekripsi Teks"):
            if key and encrypted_text_input:
                try:
                    encrypted_bytes = base64.b64decode(encrypted_text_input)  
                    decrypted_bytes = rc4_encrypt_decrypt(encrypted_bytes, key)  
                    decrypted_text = decrypted_bytes.decode(errors='ignore')  
                    st.success("Hasil Dekripsi:")
                    st.code(decrypted_text, language="text")
                except Exception as e:
                    st.error(f"Kesalahan dalam proses dekripsi: {e}")


    with tab2:
        uploaded_file = st.file_uploader("Unggah File untuk Dekripsi", 
                                         type=["xlsx", "csv", "txt", "json", "pdf", "jpg", "png", "gif", "mp4", "avi", "mov", "mkv"])
        if uploaded_file and key:
            file_data = base64.b64decode(uploaded_file.read())  
            decrypted_data = rc4_encrypt_decrypt(file_data, key)  
            output_filename_dec = f"decrypted_{uploaded_file.name}"
            if st.button("🔓 Dekripsi File"):
                st.success(f"File {uploaded_file.name} berhasil didekripsi!")
                st.download_button(
                    label="📥 Download File Didekripsi",
                    data=decrypted_data,
                    file_name=output_filename_dec,
                    mime="application/octet-stream"
                )


#DES
def generate_key(key: str):
    return key.encode().ljust(8, b'\0')[:8]


def decrypt_text(encrypted_text: str, key: str, mode: str):
    key_bytes = generate_key(key)
    encrypted_data = base64.b64decode(encrypted_text)
    
    if mode == "ECB":
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        decrypted_text = unpad(cipher.decrypt(encrypted_data), DES.block_size).decode()
    
    elif mode == "CBC":
        iv = encrypted_data[:8]
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        decrypted_text = unpad(cipher.decrypt(encrypted_data[8:]), DES.block_size).decode()
    
    elif mode == "COUNTER":
        iv = encrypted_data[:8]
        ctr = Counter.new(64, initial_value=int.from_bytes(iv, byteorder="big"))
        cipher = DES.new(key_bytes, DES.MODE_CTR, counter=ctr)
        decrypted_text = cipher.decrypt(encrypted_data[8:]).decode()
    
    return decrypted_text

### Fungsi Dekripsi File DES (tanpa base64)
def decrypt_file(encrypted_file, key: str, mode: str, original_filename: str):
    key_bytes = generate_key(key)
    encrypted_data = encrypted_file.read()
    
    if mode == "ECB":
        cipher = DES.new(key_bytes, DES.MODE_ECB)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), DES.block_size)
    
    elif mode == "CBC":
        iv = encrypted_data[:8]
        cipher = DES.new(key_bytes, DES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data[8:]), DES.block_size)
    
    elif mode == "COUNTER":
        iv = encrypted_data[:8]
        ctr = Counter.new(64, initial_value=int.from_bytes(iv, byteorder="big"))
        cipher = DES.new(key_bytes, DES.MODE_CTR, counter=ctr)
        decrypted_data = cipher.decrypt(encrypted_data[8:])
    
    return decrypted_data, original_filename

if metode == "DES":
    st.subheader("🔓 Dekripsi DES")
    key = st.text_input("Masukkan Kunci Dekripsi (8 karakter max)", max_chars=8)
    
    tab1, tab2 = st.tabs(["📝 Dekripsi Teks", "📂 Dekripsi File"])
    
    with tab1:
        encrypted_text = st.text_area("Masukkan Teks yang Akan Didekripsi")
        if st.button("🔓 Dekripsi Teks"):
            if key and encrypted_text:
                decrypted_text = decrypt_text(encrypted_text, key, mode)
                st.success("Hasil Dekripsi:")
                st.code(decrypted_text, language="text")
            else:
                st.error("Mohon masukkan teks terenkripsi dan kunci dekripsi!")
    
    with tab2:
        uploaded_file = st.file_uploader("Unggah File untuk Dekripsi", type=["txt", "pdf", "jpg", "png", "csv", "docx", "xlsx", "mp4", "mov", "avi"])
        if uploaded_file and key:
            if st.button("🔓 Dekripsi File"):
                decrypted_data, original_filename = decrypt_file(uploaded_file, key, mode, uploaded_file.name)
                st.success(f"File {original_filename} Berhasil Didekripsi!")
                st.download_button("⬇️ Download File Terdekripsi", decrypted_data, original_filename)


#AES

def generate_key(key: str):
    return key.encode('utf-8').ljust(32, b'\0')


def decrypt_text(encrypted_text, key: str, mode: str):
    key_bytes = generate_key(key)
    encrypted_data = base64.b64decode(encrypted_text)

    try:
        if mode == "ECB":
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size).decode('utf-8')

        elif mode == "CBC":
            iv = encrypted_data[:16]
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size).decode('utf-8')

        elif mode == "COUNTER":
            iv = encrypted_data[:16]
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
            cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
            decrypted_data = cipher.decrypt(encrypted_data[16:]).decode('utf-8')

        return decrypted_data
    except Exception as e:
        return f"Gagal mendekripsi teks: {str(e)}"


def decrypt_file(input_file, key, mode):
    key_bytes = generate_key(key)
    encrypted_data = input_file.read()

    try:
        if mode == "ECB":
            cipher = AES.new(key_bytes, AES.MODE_ECB)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

        elif mode == "CBC":
            iv = encrypted_data[:AES.block_size]
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)

        elif mode == "COUNTER":
            iv = encrypted_data[:16]  # Ambil IV dari awal ciphertext
            ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder="big"))
            cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
            decrypted_data = cipher.decrypt(encrypted_data[16:])  # Dekripsi mulai dari byte ke-16

        return decrypted_data
    except Exception as e:
        return f"Gagal mendekripsi file: {str(e)}"


if metode == "AES":
    st.subheader("🔓 Dekripsi AES")
    key = st.text_input("Masukkan Kunci Dekripsi (maks 32 karakter)", max_chars=32)

    tab1, tab2 = st.tabs(["🔓 Dekripsi Teks", "📂 Dekripsi File"])

    with tab1:
        encrypted_text = st.text_area("Masukkan Teks Terenkripsi")
        if st.button("🔓 Dekripsi Teks"):
            if key and encrypted_text:
                decrypted_text = decrypt_text(encrypted_text, key, mode)
                st.success("Hasil Dekripsi:")
                st.code(decrypted_text, language="text")
            else:
                st.error("Mohon masukkan teks terenkripsi dan kunci dekripsi!")

    with tab2:
        uploaded_file = st.file_uploader("Unggah File Terenkripsi", type=[
            "txt", "pdf", "jpg", "png", "csv", "docx", "xlsx", "mp4", "mov", "avi"
        ])
        if uploaded_file and key:
            if st.button("🔓 Dekripsi File"):
                decrypted_data = decrypt_file(uploaded_file, key, mode)
                st.success(f"File {uploaded_file.name} Berhasil Didekripsi!")
                st.download_button(
                    "⬇️ Download File Didekripsi", 
                    decrypted_data, 
                    file_name=f"decrypted_{uploaded_file.name}"
                )

if st.sidebar.button("❌ Logout"):
    st.session_state["authenticated"] = False
    st.rerun()


