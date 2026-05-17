# 184CourseProject

Flask demo project with:
- Local email/password authentication
- OTP verification (printed to terminal for demo)
- Optional Google OAuth login (in `app2.py`)

## Prerequisites

- Python 3.10+ (3.11 recommended)
- Git

## 1) Create and activate a virtual environment

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

## 2) Install dependencies

```powershell
python -m pip install --upgrade pip
pip install flask flask-login flask-bcrypt authlib python-dotenv
```

## 3) Optional: Configure Google OAuth (for `app2.py`)

Create a `.env` file in the project root with:

```env
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

If these values are missing, regular email/password login still works.

## 4) Run the app

Pick one app file:

```powershell
python app.py
```

or

```powershell
python app1.py
```

or

```powershell
python app2.py
```

Then open:

```text
http://127.0.0.1:5000
```

Notes:
- SQLite database file `users.db` is created automatically in the project root.
- OTP code is printed in the terminal when using OTP-enabled flows.
