User Authentication and Role Management System
A Python-based user authentication project with a Streamlit graphical
interface and a command-line interface. It demonstrates account
registration, login verification, password security, role-based access,
account locking, and administrator tools.
Project overview
The project has two runnable entry points:
- app.py --- Streamlit web interface.
- user_authentication.py --- command-line interface.
Both implementations use local text files for persistence:
- users.txt --- stores usernames, password salts, password hashes,
  roles, failed-login counts, and account-lock status.
- activity.txt --- stores timestamped activity messages.
Note: The two Python files currently contain separate copies of the
authentication logic. They are not wired together as a shared module,
so changes to one implementation should also be reviewed in the other.

Features
Authentication and account security
- User registration and login.
- Password hashing with PBKDF2-HMAC-SHA256 (200,000 iterations).
- A unique random salt generated for each new password.
- Constant-time hash comparison using hmac.compare_digest.
- Username and password validation using regular expressions.
- Account lock after three failed password attempts.
- Successful login resets the failed-attempt counter.
- Users can change their password after verifying their current
  password.
Role management
- Separate administrator and standard-user experiences.
- Admin can view users, unlock accounts, delete eligible accounts,
  inspect the activity log, and create admin accounts.
- User dashboard provides profile information and password change.
Interface and logging
- Streamlit tabs for login and registration.
- Sidebar navigation for admin and user dashboards.
- Timestamped activity logging.
- Text-file persistence between application runs.
Technology stack
- Python 3
- Streamlit
- hashlib --- PBKDF2 password hashing
- secrets --- cryptographically strong salt generation
- hmac --- constant-time hash comparison
- re --- input validation
- os --- file and path checks
- datetime --- activity timestamps
Project structure
user-authentication-role-management/
├── app.py
├── user_authentication.py
├── users.txt          # created automatically on first run
├── activity.txt       # created automatically on first run
└── README.md
Setup
1. Install Python 3.
2. Open a terminal in the project folder.
3. (Recommended) Create and activate a virtual environment:
   python -m venv .venv
   Windows PowerShell:
   .\.venv\Scripts\Activate.ps1
4. Install Streamlit:
   pip install streamlit
The command-line version uses Python standard-library modules and does
not require Streamlit.
Run the application
Streamlit interface
streamlit run app.py
Streamlit will print a local URL in the terminal. Open that URL in your
browser.
Command-line interface
python user_authentication.py
The application creates users.txt and activity.txt if they do not
already exist.
Default administrator account
The current source code initializes this account when users.txt does
not exist:
- Username: admin
- Password: Admin@123
Change the default credential before sharing or deploying the project.
Do not publish real credentials or populated users.txt /
activity.txt files in a public repository. If the files already exist,
deleting them is not a safe way to reset a real deployment because it
removes stored accounts and logs.
Validation rules
Username
- 3 to 20 characters.
- Letters, digits, and underscore only.
Password
- At least 8 characters.
- At least one uppercase letter.
- At least one lowercase letter.
- At least one digit.
- At least one permitted special character: @$!%*?&.
