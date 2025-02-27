import streamlit as st
import base64
import pandas as pd
import matplotlib.pyplot as plt

if "authenticated" not in st.session_state or not st.session_state["authenticated"]:
    st.warning("🔒 Anda harus login terlebih dahulu!")
    st.stop()  # Menghentikan eksekusi halaman jika belum login


# Konfigurasi Halaman
st.set_page_config(
    page_title="🔒 Enkripsi & Dekripsi Data",
    page_icon="🔑",
    layout="wide"
)

# --- SIDEBAR NAVIGASI ---
st.sidebar.title("📌 Navigasi")
menu = st.sidebar.selectbox("Pilih Menu", ["🏠 Dashboard", "❓ FAQ", "ℹ️ Tentang"])

# --- DASHBOARD ---
if menu == "🏠 Dashboard":
    st.title("🔒 Dashboard - Sistem Enkripsi & Dekripsi Data")
    st.write("Selamat datang di aplikasi keamanan data! Pilih metode enkripsi dan dekripsi dari menu di sebelah kiri.")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(label="🔐 Total Enkripsi", value="47", delta="+5 hari ini")

    with col2:
        st.metric(label="🔓 Total Dekripsi", value="39", delta="+3 hari ini")

    with col3:
        st.metric(label="🔑 Metode Tersedia", value="4",)

    st.markdown("---")

# --- FAQ ---
elif menu == "❓ FAQ":
    st.title("❓ Pertanyaan Umum (FAQ)")
    
    with st.expander("🔐 Apa itu Enkripsi?"):
        st.write("Enkripsi adalah Proses mengubah data atau pesan menjadi bentuk yang tidak dapat dibaca tanpa kunci tertentu. Tujuannya adalah melindungi informasi agar hanya pihak yang memiliki kunci dekripsi yang bisa mengakses isi pesan tersebut. Contoh algoritma enkripsi: AES, RSA, dan DES.")

    with st.expander("🔓 Apa itu Dekripsi?"):
        st.write("Dekripsi adalah Proses kebalikan dari enkripsi, yaitu mengubah data yang telah dienkripsi (ciphertext) kembali ke bentuk aslinya (plaintext) menggunakan kunci dekripsi yang sesuai.")


# --- INFORMASI TENTANG APLIKASI ---
elif menu == "ℹ️ Tentang":
    st.title("ℹ️ Tentang Aplikasi")
    st.write("Aplikasi ini dibuat untuk mempermudah enkripsi dan dekripsi berbagai jenis data ")
    st.write("🔑 Metode yang tersedia: **XOR, RC4, AES Cipher, DES Cipher**")
    st.write("💡 Pastikan untuk menjaga keamanan kunci enkripsi!")

    st.markdown("### 🔗 Kontak Pengembang")
    st.write("📧 Email: alfredzebua20@gmail.com | yoel.simbolon97@gmail.com")

if st.sidebar.button("❌ Logout"):
    st.session_state["authenticated"] = False
    st.rerun()