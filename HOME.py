import streamlit as st

st.set_page_config(page_title="🔒 Login", page_icon="🔑")

def load_css(file_name):
    with open(file_name) as f:
        css = f.read()
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

# Panggil file CSS dari folder assets
load_css("assets/style.css")

# Simpan status login di session_state
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

# Fungsi login
def login():
    username = st.text_input("Username", placeholder="Masukkan username")
    password = st.text_input("Password", type="password", placeholder="Masukkan password")
    
    if st.button("🔓 Login"):
        if username == "admin" and password == "admin":
            st.session_state["authenticated"] = True
            st.success("Login berhasil! Anda dapat mengakses menu lainnya.")
            st.rerun()
        else:
            st.error("Username atau password salah!")

# Jika sudah login, beri akses ke halaman lain
if not st.session_state["authenticated"]:
    st.title("🔑 Halaman Login")
    login()
    st.stop()  # Menghentikan akses ke halaman lain sebelum login

  