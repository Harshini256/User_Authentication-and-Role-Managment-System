# app.py - Project 24 - User Authentication and Role Management System
# Streamlit UI for main.py - Same Security: PBKDF2 + Salt + hmac
import re
import os
import hashlib
import secrets
import hmac
import streamlit as st
from datetime import datetime

USERS_FILE = "users.txt"
ACTIVITY_FILE = "activity.txt"

# ---------- SAME LOGIC AS main.py ----------
class User:
    def __init__(self, username, password, role):
        self.username = username
        self.role = role
        self.salt, self.password_hash = hash_password(password)
        self.failed = 0
        self.locked = False

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200000)
    return salt, hashed.hex()

def verify_password(password, user):
    _, new_hash = hash_password(password, user.salt)
    return hmac.compare_digest(new_hash, user.password_hash)

def create_files():
    if not os.path.exists(USERS_FILE):
        admin = User("admin", "Admin@123", "admin")
        save_users({"admin": admin})
    if not os.path.exists(ACTIVITY_FILE):
        open(ACTIVITY_FILE, "w").close()

def load_users():
    users = {}
    try:
        with open(USERS_FILE, "r") as f:
            for line in f:
                if line.strip():
                    data = line.strip().split("|")
                    if len(data) != 6: continue
                    name, salt, pwd_hash, role, fail, lock = data
                    u = User.__new__(User)
                    u.username = name; u.salt = salt; u.password_hash = pwd_hash
                    u.role = role; u.failed = int(fail); u.locked = lock == "True"
                    users[name] = u
    except (OSError, ValueError) as e:
        st.error(f"Error loading user data: {e}")
    return users

def save_users(users):
    with open(USERS_FILE, "w") as f:
        for u in users.values():
            f.write(f"{u.username}|{u.salt}|{u.password_hash}|{u.role}|{u.failed}|{u.locked}\n")

def log_activity(message):
    with open(ACTIVITY_FILE, "a") as f:
        t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{t}] {message}\n")

def check_username(name):
    return re.fullmatch(r"[A-Za-z0-9_]{3,20}", name) is not None

def check_password(password):
    pattern = r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}"
    return re.fullmatch(pattern, password) is not None

# ---------- STREAMLIT UI ----------
st.set_page_config(page_title="User Authentication And Role Management", page_icon="🔐", layout="centered")
create_files()

# Session State - Keeps user logged in
if "logged_user" not in st.session_state:
    st.session_state.logged_user = None
if "page" not in st.session_state:
    st.session_state.page = "Login"

st.title("🔐 User Authentication and Role Management")
st.subheader("Secure Login System with Role-Based Access Control")
st.caption("Secure password storage using PBKDF2-HMAC-SHA256 with 200,000 iterations and unique salts.")

# ----- IF NOT LOGGED IN : LOGIN / REGISTER -----
if st.session_state.logged_user is None:
    tab1, tab2 = st.tabs(["🔑 Login", "📝 Register"])

    with tab1:
        st.header("User Login")
        username = st.text_input("Username", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login", use_container_width=True, type="primary"):
            users = load_users()
            if username not in users:
                st.error("User not found!")
            else:
                user = users[username]
                if user.locked:
                    st.error("Account is locked! Contact admin.")
                elif verify_password(password, user):
                    user.failed = 0
                    save_users(users)
                    log_activity(f"Login successful: {username}")
                    st.session_state.logged_user = username
                    st.success(f"Welcome {username}! Role: {user.role}")
                    st.rerun()
                else:
                    user.failed += 1
                    if user.failed >= 3:
                        user.locked = True
                        st.error("Account locked after 3 failed attempts!")
                        log_activity(f"Account locked: {username}")
                    else:
                        st.error(f"Wrong password! Attempt {user.failed}/3")
                    save_users(users)
        st.info("Default Admin Login\nUsername: `admin` | Password: `Admin@123`")

    with tab2:
        st.header("User Registration")
        new_user = st.text_input("Enter username (3-20, letters/numbers/_)", key="reg_user")
        new_pass = st.text_input("Enter password", type="password", key="reg_pass")
        role = st.selectbox("Role", ["user", "admin"])
        st.caption("Password must: 8+ chars, Upper, Lower, Number, Special (@$!%*?&)")
        if st.button("Register", use_container_width=True):
            users = load_users()
            if not check_username(new_user):
                st.error("Invalid username! Use 3-20 letters, numbers or _")
            elif new_user in users:
                st.error("Username already exists!")
            elif not check_password(new_pass):
                st.error("Password must contain Upper, Lower, Number, Special char, 8+ chars")
            else:
                users[new_user] = User(new_user, new_pass, role)
                save_users(users)
                log_activity(f"Registered {new_user} as {role}")
                st.success("Registration successful! Go to Login tab.")

# ----- IF LOGGED IN -----
else:
    users = load_users()
    username = st.session_state.logged_user
    user = users.get(username)
    if not user:
        st.session_state.logged_user = None
        st.rerun()

    # Sidebar - Like Yash's Dashboard
    st.sidebar.title(f"👋 Welcome {username}")
    st.sidebar.write(f"Role: **{user.role}**")
    if st.sidebar.button("Logout"):
        st.session_state.logged_user = None
        st.rerun()

    # ===== ADMIN MENU =====
    if user.role == "admin":
        st.header("👑 Admin Dashboard")
        menu = st.sidebar.radio("Admin Menu", ["View All Users", "Unlock User", "Delete User", "View Activity Log", "Create Admin Account"])

        if menu == "View All Users":
            st.subheader("All Users")
            for u in users.values():
                status = "🔒 LOCKED" if u.locked else "✅ Active"
                st.write(f"**{u.username}** - {u.role} - {status}")

        elif menu == "Unlock User":
            st.subheader("Unlock User")
            name = st.text_input("Username to unlock")
            if st.button("Unlock"):
                if name in users:
                    users[name].locked = False; users[name].failed = 0
                    save_users(users); log_activity(f"Account unlocked: {name}")
                    st.success("User unlocked successfully!")
                else: st.error("User not found!")

        elif menu == "Delete User":
            st.subheader("Delete User")
            name = st.text_input("Username to delete")
            if st.button("Delete", type="primary"):
                if name not in users: st.error("User not found!")
                elif name == username: st.error("You cannot delete your own account!")
                elif name == "admin": st.error("Default admin cannot be deleted!")
                elif users[name].role=="admin" and sum(1 for x in users.values() if x.role=="admin")<=1:
                    st.error("Cannot delete the last admin!")
                else:
                    del users[name]; save_users(users); log_activity(f"User deleted: {name}")
                    st.success("User deleted successfully!"); st.rerun()

        elif menu == "View Activity Log":
            st.subheader("Activity Log")
            try: st.code(open(ACTIVITY_FILE).read())
            except: st.error("Activity file unavailable!")

        elif menu == "Create Admin Account":
            st.subheader("Create Admin Account")
            au = st.text_input("New Admin Username")
            ap = st.text_input("New Admin Password", type="password")
            if st.button("Create Admin"):
                if not check_username(au): st.error("Invalid username!")
                elif au in users: st.error("Username exists!")
                elif not check_password(ap): st.error("Invalid password!")
                else:
                    users[au] = User(au, ap, "admin"); save_users(users)
                    log_activity(f"Registered {au} as admin"); st.success("Admin created!")

    # ===== USER MENU =====
    else:
        st.header("👤 User Dashboard")
        menu = st.sidebar.radio("User Menu", ["My Profile", "Change Password"])
        if menu == "My Profile":
            st.subheader("My Profile")
            st.write(f"**Username:** {user.username}")
            st.write(f"**Role:** {user.role}")
            st.write(f"**Status:** {'Locked' if user.locked else 'Active'}")
        elif menu == "Change Password":
            st.subheader("Change Password")
            old = st.text_input("Old password", type="password")
            new = st.text_input("New password", type="password")
            if st.button("Change Password", type="primary"):
                if verify_password(old, user):
                    if check_password(new):
                        user.salt, user.password_hash = hash_password(new)
                        save_users(users); log_activity(f"Password changed: {username}")
                        st.success("Password changed successfully!")
                    else: st.error("Invalid new password!")
                else: st.error("Old password is incorrect!")

st.divider()
st.caption("User Authentication and Role Management System are implemented in Python using PBKDF2 + Salt for secure password storage, with a Streamlit UI and TXT file storage for user data and activity logs.")