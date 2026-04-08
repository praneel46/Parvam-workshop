from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import sqlite3
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "your-secret-key"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, "users.db")

# connection to the database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


# Closing the connection
@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# For creating the database and creating the table
def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            mobile TEXT UNIQUE,
            gender TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            phone TEXT NOT NULL,
            dob TEXT NOT NULL,
            address TEXT NOT NULL,
            pincode TEXT NOT NULL,
            college TEXT NOT NULL,
            branch TEXT NOT NULL,
            section TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            deleted_at TIMESTAMP NULL
        )
        """
    )
    db.commit()


# Table is created and stored in db
def setup_database():
    init_db()


with app.app_context():
    setup_database()


def generate_student_id():
    db = get_db()
    result = db.execute("SELECT MAX(id) as max_id FROM students").fetchone()
    next_id = (result['max_id'] or 0) + 1
    return f"SJB-{next_id:03d}"


# To check the password format
def validate_password(password):
    # Check for min 8 to max 14 characters, if it is not there show this message
    if len(password) < 8 or len(password) > 14:
        return False, "Password must be between 8 and 14 characters."
    # Check the existence of atleast 1 uppercase character([A-Z])
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    # Check the existence of atleast 1 lowercase character([a-z])
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    # Check the existence of atleast 1 number character([0-9] or \d)
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    # Check the existence of atleast 1 special character from the given set([!@#$%^&*(),.?":{}|<>])
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, ""


def validate_phone(phone):
    # Check if phone is exactly 10 digits and starts with 6,7,8, or 9
    if not re.match(r'^[6789]\d{9}$', phone):
        return False, "Phone number must be 10 digits and start with 6, 7, 8, or 9."
    return True, ""


# Base Route will redirect to login route
@app.route("/")
def index():
    return redirect(url_for("login"))

# Route for Signup page
# methods: GET for showing the empty Signup form
# POST for storing or inserting or creating the new account
@app.route("/signup", methods=["GET", "POST"])
def signup():
    form_data = {}
    if request.method == "POST":
        # using strip() method to eliminate the white space or empty space
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        mobile = request.form.get("mobile", "").strip()
        gender = request.form.get("gender", "").strip()

        # form_data object is created with the request information 
        form_data = {
            'name': name,
            'email': email,
            'mobile': mobile,
            'gender': gender
        }

        # check whether all information is given by the user, if not given show the validation message
        if not name or not email or not password or not confirm:
            flash("Please fill out all required fields.", "warning")
            return render_template("signup.html", form_data=form_data)

        # check for the same password in password and confirm password fields
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("signup.html", form_data=form_data)

        # Validate password strength

        # danger refers to red color
        # success refers to green color
        valid, msg = validate_password(password)
        if not valid:
            flash(msg, "danger")
            return render_template("signup.html", form_data=form_data)

        # To check the uniqueness of the email id or is it taken by other user
        db = get_db()
        existing_email = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if existing_email:
            flash("An account with that email already exists.", "danger")
            return render_template("signup.html", form_data=form_data)

        # To check the uniqueness of the phone number or is it taken by other user
        if mobile:
            existing_mobile = db.execute("SELECT * FROM users WHERE mobile = ?", (mobile,)).fetchone()
            if existing_mobile:
                flash("An account with that mobile number already exists.", "danger")
                return render_template("signup.html", form_data=form_data)

        # Password is stored in hash format to secure it

        # If everything is fine, then create a new account or store the user details in db
        hashed_password = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (name, email, password, mobile, gender) VALUES (?, ?, ?, ?, ?)",
            (name, email, hashed_password, mobile, gender),
        )
        db.commit()

        # Show success message and redirect the user to login page.
        flash("Signup successful! Redirecting to login page...", "success")
        return render_template("signup.html", redirect=True, form_data={})

    return render_template("signup.html", form_data=form_data)


# Route to go for login page

# Get for showing the login page

# Post for checking the credentials
@app.route("/login", methods=["GET", "POST"])
def login():
    form_data = {}
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        form_data = {'email': email}

        # To ask user to enter both details 
        if not email or not password:
            flash("Please enter your email and password.", "warning")
            return render_template("login.html", form_data=form_data)

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password"],
         password):
            # If login is success then store the user details in session
            session["user_id"] = user["id"]
            return redirect(url_for("welcome"))
        # If the credentials is matching with stored record then send the user to welcome page

        # If password or email is not correct show this message
        flash("Invalid email or password.", "danger")
        return render_template("login.html", form_data=form_data)

    return render_template("login.html", form_data=form_data)


# Route for Welcome page
@app.route("/welcome")
def welcome():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    # To show the details in Welcome page, we will fetch the data
    db = get_db()
    user = db.execute("SELECT id, name, email, mobile, gender FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        flash("User not found.", "danger")
        return redirect(url_for("login"))

    return render_template("welcome.html", user=user)

# route for logout
@app.route("/logout")
def logout():
    # clear the session of the user if logged out.
    session.pop("user_id", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/students")
def students():
    if not session.get("user_id"):
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    db = get_db()
    students_list = db.execute("SELECT * FROM students WHERE deleted_at IS NULL ORDER BY created_at DESC").fetchall()
    return render_template("students.html", students=students_list)


@app.route("/students/add", methods=["GET", "POST"])
def add_student():
    if not session.get("user_id"):
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    form_data = {}
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        dob = request.form.get("dob", "")
        address = request.form.get("address", "").strip()
        pincode = request.form.get("pincode", "").strip()
        college = request.form.get("college", "").strip()
        branch = request.form.get("branch", "").strip()
        section = request.form.get("section", "").strip()

        form_data = {
            'name': name,
            'email': email,
            'phone': phone,
            'dob': dob,
            'address': address,
            'pincode': pincode,
            'college': college,
            'branch': branch,
            'section': section
        }

        if not all([name, email, phone, dob, address, pincode, college, branch, section]):
            flash("Please fill out all required fields.", "warning")
            return render_template("add_student.html", form_data=form_data)

        # Validate phone number format
        valid_phone, phone_msg = validate_phone(phone)
        if not valid_phone:
            flash(phone_msg, "danger")
            return render_template("add_student.html", form_data=form_data)

        db = get_db()
        existing_email = db.execute("SELECT * FROM students WHERE email = ? AND deleted_at IS NULL", (email,)).fetchone()
        if existing_email:
            flash("A student with that email already exists.", "danger")
            return render_template("add_student.html", form_data=form_data)

        existing_phone = db.execute("SELECT * FROM students WHERE phone = ? AND deleted_at IS NULL", (phone,)).fetchone()
        if existing_phone:
            flash("A student with that phone number already exists.", "danger")
            return render_template("add_student.html", form_data=form_data)

        student_id = generate_student_id()
        db.execute(
            """
            INSERT INTO students (student_id, name, email, phone, dob, address, pincode, college, branch, section)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (student_id, name, email, phone, dob, address, pincode, college, branch, section),
        )
        db.commit()
        flash(f"Student {student_id} added successfully!", "success")
        return redirect(url_for("students"))

    return render_template("add_student.html", form_data=form_data)


@app.route("/students/<int:student_id>")
def view_student(student_id):
    if not session.get("user_id"):
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id = ? AND deleted_at IS NULL", (student_id,)).fetchone()
    if not student:
        flash("Student not found.", "danger")
        return redirect(url_for("students"))

    return render_template("view_student.html", student=student)


@app.route("/students/<int:student_id>/edit", methods=["GET", "POST"])
def edit_student(student_id):
    if not session.get("user_id"):
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id = ? AND deleted_at IS NULL", (student_id,)).fetchone()
    if not student:
        flash("Student not found.", "danger")
        return redirect(url_for("students"))

    form_data = {}
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        dob = request.form.get("dob", "")
        address = request.form.get("address", "").strip()
        pincode = request.form.get("pincode", "").strip()
        college = request.form.get("college", "").strip()
        branch = request.form.get("branch", "").strip()
        section = request.form.get("section", "").strip()

        form_data = {
            'name': name,
            'email': email,
            'phone': phone,
            'dob': dob,
            'address': address,
            'pincode': pincode,
            'college': college,
            'branch': branch,
            'section': section
        }

        if not all([name, email, phone, dob, address, pincode, college, branch, section]):
            flash("Please fill out all required fields.", "warning")
            return render_template("edit_student.html", student=student, form_data=form_data)

        # Validate phone number format
        valid_phone, phone_msg = validate_phone(phone)
        if not valid_phone:
            flash(phone_msg, "danger")
            return render_template("edit_student.html", student=student, form_data=form_data)

        existing_email = db.execute("SELECT * FROM students WHERE email = ? AND id != ? AND deleted_at IS NULL", (email, student_id)).fetchone()
        if existing_email:
            flash("A student with that email already exists.", "danger")
            return render_template("edit_student.html", student=student, form_data=form_data)

        existing_phone = db.execute("SELECT * FROM students WHERE phone = ? AND id != ? AND deleted_at IS NULL", (phone, student_id)).fetchone()
        if existing_phone:
            flash("A student with that phone number already exists.", "danger")
            return render_template("edit_student.html", student=student, form_data=form_data)

        db.execute(
            """
            UPDATE students SET name=?, email=?, phone=?, dob=?, address=?, pincode=?, college=?, branch=?, section=?, updated_at=CURRENT_TIMESTAMP
            WHERE id=?
            """,
            (name, email, phone, dob, address, pincode, college, branch, section, student_id),
        )
        db.commit()
        flash("Student updated successfully!", "success")
        return redirect(url_for("view_student", student_id=student_id))

    form_data = {
        'name': student['name'],
        'email': student['email'],
        'phone': student['phone'],
        'dob': student['dob'],
        'address': student['address'],
        'pincode': student['pincode'],
        'college': student['college'],
        'branch': student['branch'],
        'section': student['section']
    }
    return render_template("edit_student.html", student=student, form_data=form_data)


@app.route("/students/<int:student_id>/delete", methods=["POST"])
def delete_student(student_id):
    if not session.get("user_id"):
        flash("Please log in to continue.", "warning")
        return redirect(url_for("login"))

    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id = ? AND deleted_at IS NULL", (student_id,)).fetchone()
    if not student:
        flash("Student not found.", "danger")
        return redirect(url_for("students"))

    db.execute("UPDATE students SET deleted_at=CURRENT_TIMESTAMP WHERE id=?", (student_id,))
    db.commit()
    flash("Student deleted successfully!", "success")
    return redirect(url_for("students"))


if __name__ == "__main__":
    app.run(debug=True)

