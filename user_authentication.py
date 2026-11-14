import re
import os
import hashlib
import secrets
import hmac
from datetime import datetime

USERS_FILE = "users.txt"
ACTIVITY_FILE = "activity.txt"

# USER CLASS - Encapsulation
class User:
    def __init__(self, username, password, role):
        self.username = username
        self.role = role
        self.salt, self.password_hash = hash_password(password)
        self.failed = 0
        self.locked = False

# PASSWORD HASHING - Security
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        bytes.fromhex(salt),
        200000
    )
    return salt, hashed.hex()

def verify_password(password, user):
    _, new_hash = hash_password(password, user.salt)
    return hmac.compare_digest(new_hash, user.password_hash)

# CREATE FILES
def create_files():
    if not os.path.exists(USERS_FILE):
        admin = User("admin", "Admin@123", "admin")
        save_users({"admin": admin})
    if not os.path.exists(ACTIVITY_FILE):
        with open(ACTIVITY_FILE, "w") as file:
            pass

# LOAD USERS - TXT File Handling
def load_users():
    users = {}
    try:
        with open(USERS_FILE, "r") as file:
            for line in file:
                if line.strip():
                    data = line.strip().split("|")
                    if len(data) != 6:
                        raise ValueError("Invalid user record")
                    name, salt, pwd_hash, role, fail, lock = data
                    if role not in ("admin", "user"):
                        raise ValueError("Invalid role")
                    u = User.__new__(User)
                    u.username = name
                    u.salt = salt
                    u.password_hash = pwd_hash
                    u.role = role
                    u.failed = int(fail)
                    u.locked = lock == "True"
                    users[name] = u
    except (OSError, ValueError) as error:
        print("Error loading user data:", error)
    return users

# SAVE USERS
def save_users(users):
    with open(USERS_FILE, "w") as file:
        for u in users.values():
            file.write(
                f"{u.username}|{u.salt}|{u.password_hash}|"
                f"{u.role}|{u.failed}|{u.locked}\n"
            )

# ACTIVITY LOG - Activity Summary
def log_activity(message):
    with open(ACTIVITY_FILE, "a") as file:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"[{current_time}] {message}\n")

# USERNAME VALIDATION - Regex
def check_username(name):
    return re.fullmatch(r"[A-Za-z0-9_]{3,20}", name) is not None

# PASSWORD VALIDATION - Regex
def check_password(password):
    pattern = (
        r"(?=.*[a-z])"
        r"(?=.*[A-Z])"
        r"(?=.*\d)"
        r"(?=.*[@$!%*?&])"
        r"[A-Za-z\d@$!%*?&]{8,}"
    )
    return re.fullmatch(pattern, password) is not None

# USER REGISTRATION
def register(role="user"):
    users = load_users()
    print("\n===== USER REGISTRATION =====")
    username = input("Enter username: ").strip()
    if not check_username(username):
        print("Invalid username! Use 3-20 letters, numbers or _")
        return
    if username in users:
        print("Username already exists!")
        return
    password = input("Enter password: ")
    if not check_password(password):
        print("Password must contain:")
        print("- Minimum 8 characters")
        print("- Uppercase letter")
        print("- Lowercase letter")
        print("- Number")
        print("- Special character (@$!%*?&)")
        return
    users[username] = User(username, password, role)
    save_users(users)
    log_activity(f"Registered {username} as {role}")
    print("Registration successful!")

# LOGIN - Failed Tracking + Locking
def login():
    users = load_users()
    print("\n===== USER LOGIN =====")
    username = input("Username: ").strip()
    password = input("Password: ")
    if username not in users:
        print("User not found!")
        return
    user = users[username]
    if user.locked:
        print("Account is locked! Contact admin.")
        return
    if verify_password(password, user):
        user.failed = 0
        save_users(users)
        log_activity(f"Login successful: {username}")
        print(f"\nWelcome {username}!")
        print(f"Role: {user.role}")
        if user.role == "admin":
            admin_menu(username)
        else:
            user_menu(username)
    else:
        user.failed += 1
        print(f"Wrong password! Attempt {user.failed}/3")
        if user.failed >= 3:
            user.locked = True
            print("Account locked after 3 failed attempts!")
            log_activity(f"Account locked: {username}")
        save_users(users)

# ADMIN MENU - Role-Based Access
def admin_menu(admin_name):
    while True:
        print("\n===== ADMIN MENU =====")
        print("1. View all users")
        print("2. Unlock user")
        print("3. Delete user")
        print("4. View activity log")
        print("5. Create admin account")
        print("6. Logout")
        ch = input("Choose: ").strip()
        users = load_users()
        if ch == "1":
            print("\n===== ALL USERS =====")
            for u in users.values():
                status = "LOCKED" if u.locked else "Active"
                print(f"{u.username} - {u.role} - {status}")
        elif ch == "2":
            name = input("Username to unlock: ").strip()
            if name in users:
                users[name].locked = False
                users[name].failed = 0
                save_users(users)
                log_activity(f"Account unlocked: {name}")
                print("User unlocked successfully!")
            else:
                print("User not found!")
        elif ch == "3":
            name = input("Username to delete: ").strip()
            if name not in users:
                print("User not found!")
            elif name == admin_name:
                print("You cannot delete your own account!")
            elif name == "admin":
                print("Default admin account cannot be deleted!")
            elif name in users and users[name].role == "admin" and sum(1 for u in users.values() if u.role == "admin") <= 1:
                print("Cannot delete the last admin account!")
            else:
                del users[name]
                save_users(users)
                log_activity(f"User deleted: {name}")
                print("User deleted successfully!")
        elif ch == "4":
            print("\n===== ACTIVITY LOG =====")
            try:
                with open(ACTIVITY_FILE, "r") as file:
                    print(file.read())
            except OSError:
                print("Activity file unavailable!")
        elif ch == "5":
            register("admin")
        elif ch == "6":
            print("Admin logged out.")
            break
        else:
            print("Invalid choice! Try again.")

# USER MENU - Password Reset + Profile
def user_menu(username):
    while True:
        print("\n===== USER MENU =====")
        print("1. My Profile")
        print("2. Change Password")
        print("3. Logout")
        ch = input("Choose: ").strip()
        if ch == "1":
            users = load_users()
            if username in users:
                u = users[username]
                print("\n===== MY PROFILE =====")
                print("Username:", u.username)
                print("Role:", u.role)
        elif ch == "2":
            users = load_users()
            if username not in users:
                print("Account not found!")
                break
            old = input("Enter old password: ")
            if verify_password(old, users[username]):
                new = input("Enter new password: ")
                if check_password(new):
                    users[username].salt, users[username].password_hash = hash_password(new)
                    save_users(users)
                    log_activity(f"Password changed: {username}")
                    print("Password changed successfully!")
                else:
                    print("Invalid new password!")
            else:
                print("Old password is incorrect!")
        elif ch == "3":
            print("User logged out.")
            break
        else:
            print("Invalid choice! Try again.")

# MAIN
def main():
    create_files()
    print("\nDefault Admin Login:")
    print("Username: admin")
    print("Password: Admin@123")
    while True:
        print("\n===== USER AUTHENTICATION SYSTEM =====")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            register()
        elif choice == "2":
            login()
        elif choice == "3":
            print("Thank you for using our system!")
            break
        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
