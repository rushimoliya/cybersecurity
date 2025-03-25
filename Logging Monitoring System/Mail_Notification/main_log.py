import smtplib
import base64
import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from sqlite3 import Error
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# 🔒 Encrypted credentials (Base64 encoding)
ENC_EMAIL = "dGVhbWN5YmVyMTc1QGdtYWlsLmNvbQ=="  # Replace with base64 encoded email
ENC_PASSWORD = "aG5sdyB5YXFnIGh1c2Ygc3VpbQ=="  # Replace with base64 encoded password

# Function to decode credentials
def decode_credentials():
    email = base64.b64decode(ENC_EMAIL).decode("utf-8")
    password = base64.b64decode(ENC_PASSWORD).decode("utf-8")
    return email, password

# Database setup
def create_connection(db_file):
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print(f"Connected to SQLite database: {db_file}")
    except Error as e:
        print(f"Error connecting to database: {e}")
    return conn

def create_table(conn):
    try:
        sql_create_users_table = """CREATE TABLE IF NOT EXISTS users (
                                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                                    email TEXT NOT NULL UNIQUE,
                                    password TEXT NOT NULL
                                );"""
        sql_create_login_attempts_table = """CREATE TABLE IF NOT EXISTS login_attempts (
                                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                                            email TEXT NOT NULL UNIQUE,
                                            attempts INTEGER DEFAULT 0
                                        );"""
        cursor = conn.cursor()
        cursor.execute(sql_create_users_table)
        cursor.execute(sql_create_login_attempts_table)
        conn.commit()
    except Error as e:
        print(f"Error creating table: {e}")

def add_user(conn, email, password):
    try:
        sql = '''INSERT INTO users(email, password) VALUES(?,?)'''
        cursor = conn.cursor()
        cursor.execute(sql, (email, password))
        conn.commit()
        print(f"User {email} added to the database.")
        return True  # Success
    except Error as e:
        print(f"Error inserting user: {e}")
        return False  # Failure

def get_user(conn, email):
    try:
        sql = '''SELECT * FROM users WHERE email = ?'''
        cursor = conn.cursor()
        cursor.execute(sql, (email,))
        return cursor.fetchone()
    except Error as e:
        print(f"Error fetching user: {e}")
        return None

def update_login_attempts(conn, email, attempts):
    try:
        cursor = conn.cursor()
        # Check if the email already exists in the table
        cursor.execute("SELECT * FROM login_attempts WHERE email = ?", (email,))
        result = cursor.fetchone()

        if result:  # If user exists, update the attempts
            cursor.execute("UPDATE login_attempts SET attempts = ? WHERE email = ?", (attempts, email))
        else:  # If user does not exist, insert a new record
            cursor.execute("INSERT INTO login_attempts (email, attempts) VALUES (?, ?)", (email, attempts))
        
        conn.commit()
        print(f"Updated login attempts for {email}: {attempts}")  # Debugging
    except Error as e:
        print(f"Error updating login attempts: {e}")

def get_login_attempts(conn, email):
    try:
        sql = '''SELECT attempts FROM login_attempts WHERE email = ?'''
        cursor = conn.cursor()
        cursor.execute(sql, (email,))
        result = cursor.fetchone()

        if result:
            attempts = result[0]

            # Reset attempts if the program is restarted (new session)
            if attempts >= 4:
                update_login_attempts(conn, email, 0)  # Reset after restart
                return 0  # Return 0 so the user gets fresh attempts

            return attempts
        else:
            return 0
    except Error as e:
        print(f"Error fetching login attempts: {e}")
        return 0


# Email sending function
def send_email(to_email, subject, message):
    try:
        email, password = decode_credentials()  # Get decrypted credentials

        # Create an email message using MIME
        msg = MIMEMultipart()
        msg["From"] = email
        msg["To"] = to_email
        msg["Subject"] = subject

        # Attach message with proper UTF-8 encoding
        msg.attach(MIMEText(message, "plain", "utf-8"))

        # Connect to SMTP Server
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(email, password)  # Use credentials securely
            server.sendmail(email, to_email, msg.as_string())  # Send MIME formatted email
        
        print("✅ Email sent successfully!")
    except Exception as e:
        print("❌ Email sending failed:", e)

# Login check function
def check_login():
    email = email_entry.get()
    password = password_entry.get()

    conn = create_connection("users.db")
    if conn is not None:
        user = get_user(conn, email)  # Fetch user details

        if not user:  # ✅ If email is not in the database
            response = messagebox.askyesno("User Not Found", "This email is not registered. Do you want to create an account?")
            if response:
                register_email_entry.insert(0, email)  # Pre-fill registration email field
                root.after(500, lambda: register_email_entry.focus())  # Move focus to registration
            return  # Exit function

        if user[2] == password:  # user[2] is the password field
            messagebox.showinfo("Login Successful", "✅ Login Successful!")
            send_email(email, "Login Alert", "Your account was just logged in successfully.")
            update_login_attempts(conn, email, 0)  # Reset attempts after success
            root.after(1000, clear_fields)
        else:
            attempts = get_login_attempts(conn, email) + 1  
            update_login_attempts(conn, email, attempts)  

            if attempts >= 4:
                send_email(email, "Security Alert", "⚠️ Unusual login activity detected on your account.")
                messagebox.showwarning("Warning", "⚠️ Unusual login activity detected! An email has been sent to you.")
            else:
                remaining_attempts = 4 - attempts
                messagebox.showerror("Login Failed", f"❌ Invalid credentials. Attempts left: {remaining_attempts}")

        conn.close()


# Clear fields function
def clear_fields():
    email_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

# Register user function
def register_user():
    email = register_email_entry.get()
    password = register_password_entry.get()

    if email and password:
        conn = create_connection("users.db")
        if conn is not None:
            # Check if user already exists
            if get_user(conn, email):
                messagebox.showinfo("Already Registered", "You have already registered. Please login.")
            else:
                # Add new user
                if add_user(conn, email, password):
                    messagebox.showinfo("Registration Successful", "✅ User registered successfully!")
                    send_email(email, "Registration Successful", "You have successfully registered!")
                    register_email_entry.delete(0, tk.END)
                    register_password_entry.delete(0, tk.END)
                else:
                    messagebox.showerror("Error", "Failed to register user.")
            conn.close()
    else:
        messagebox.showwarning("Input Error", "Please enter both email and password.")

# GUI Setup
root = tk.Tk()
root.title("🔒 Secure Login Form")
root.geometry("900x600")

style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=6)
style.configure("TLabel", font=("Arial", 12))
style.configure("TEntry", font=("Arial", 12), padding=5)

# Login Frame
login_frame = tk.Frame(root, bg="white", padx=20, pady=20, relief="solid", bd=1)
login_frame.place(relx=0.5, rely=0.4, anchor="center")

ttk.Label(login_frame, text="📧 Email:", background="white").grid(row=0, column=0, sticky="w", pady=5)
email_entry = ttk.Entry(login_frame, width=30)
email_entry.grid(row=0, column=1, pady=5)

ttk.Label(login_frame, text="🔑 Password:", background="white").grid(row=1, column=0, sticky="w", pady=5)
password_entry = ttk.Entry(login_frame, width=30, show="*")
password_entry.grid(row=1, column=1, pady=5)

login_button = ttk.Button(login_frame, text="🔓 Login", command=check_login)
login_button.grid(row=2, columnspan=2, pady=10)

# Registration Frame
register_frame = tk.Frame(root, bg="white", padx=20, pady=20, relief="solid", bd=1)
register_frame.place(relx=0.5, rely=0.7, anchor="center")

ttk.Label(register_frame, text="📧 Email:", background="white").grid(row=0, column=0, sticky="w", pady=5)
register_email_entry = ttk.Entry(register_frame, width=30)
register_email_entry.grid(row=0, column=1, pady=5)

ttk.Label(register_frame, text="🔑 Password:", background="white").grid(row=1, column=0, sticky="w", pady=5)
register_password_entry = ttk.Entry(register_frame, width=30, show="*")
register_password_entry.grid(row=1, column=1, pady=5)

register_button = ttk.Button(register_frame, text="📝 Register", command=register_user)
register_button.grid(row=2, columnspan=2, pady=10)

# Initialize database
conn = create_connection("users.db")
if conn is not None:
    create_table(conn)
    conn.close()

root.mainloop()