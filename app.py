from flask import Flask,render_template,redirect,request,url_for,flash,session
import mysql.connector,secrets,time,smtplib,hashlib,os,hmac
from email.message import EmailMessage
from werkzeug.security import generate_password_hash,check_password_hash

app=Flask(__name__)
app.secret_key="change this to a random secret"

def getdb():
    return mysql.connector.connect(
        host='localhost', user='root',
        password='211013', database='Sign_up',
        use_pure=True
    )

@app.route("/")
def signova():
    return render_template("signova.html")

@app.route("/home")
def home():
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/signup",methods=['GET','POST'])
def signup():
    if request.method == "POST":
        username=request.form["username"].strip()
        email=request.form["email"].strip()
        password=request.form["password"]
        confirm=request.form["confirm_password"]

        if password!=confirm:
            flash("Passwords do not match.","error")
            return redirect(url_for("signup"))

        conn=getdb()
        cursor=conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users(username,email,password_hash) VALUES (%s,%s,%s)" ,
                (username,email,generate_password_hash(password))
            )
            conn.commit()
        except mysql.connector.IntegrityError:
            flash("Username or Email already exists.","error")
            return redirect(url_for("signup"))
        
        finally:
            cursor.close()
            conn.close()

        session ["new_user"]=username
        return redirect(url_for("submit"))
    
    return render_template("index.html")

@app.route("/login",methods=['GET','POST'])
def login():
        if request.method=='POST':
            login=request.form['login'].strip()
            password=request.form['password']

            conn=getdb()
            cursor=conn.cursor(dictionary=True)

            try:
                cursor.execute(
                    "SELECT * FROM users WHERE email=%s or username=%s",
                    (login,login)
                )

                user=cursor.fetchone()

                if user and check_password_hash(user["password_hash"],password):

                    session["user_id"]=user["id"]
                    session["username"]=user["username"]

                    return redirect(url_for("welcomeback"))

                else:
                    flash("Username or Email doesn't exists.","error")
                    return redirect(url_for("login"))

            finally:
                cursor.close()
                conn.close()
        return render_template("login.html")

OTP_TTL=300
MAX_ATTEMPTS=5

def hash_otp(otp):
    return hmac.new(app.secret_key.encode(),otp.encode(),hashlib.sha256).hexdigest()

def send_otp_email(to_email,otp):
    msg=EmailMessage()
    msg["Subject"]="Your OTP"
    msg["From"]=os.environ["MAIL_USER"]
    msg["To"]=to_email
    msg.set_content(f"Your Verfication Code is {otp}.It will expire in 5 minutes!")
    with smtplib.SMTP_SSL("smtp.gmail.com",465) as server:
        server.login(os.environ["MAIL_USER"],os.environ["MAIL_APP_PASSWORD"])
        server.send_message(msg)


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email", "").strip()

        if not email:
            flash("Please enter your email.", "error")
            return redirect(url_for("forgot"))

        conn = getdb()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute(
                "SELECT * FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()
        finally:
            cursor.close()
            conn.close()

        if not user:
            flash("Email is not registered!", "info")
            return redirect(url_for("forgot"))

        otp = str(secrets.randbelow(1000000)).zfill(6)

        session["reset"] = {
            "email": email,
            "otp_hash": hash_otp(otp),
            "expiry": time.time() + OTP_TTL,
            "attempts": 0
        }

        try:
            send_otp_email(email, otp)
        except Exception as e:
            print("Email error:", e)
            session.pop("reset", None)
            flash("Unable to send code. Please try again.", "error")
            return redirect(url_for("forgot"))

        flash("Verification Code has been sent through gmail.", "info")
        return redirect(url_for("verify_otp"))

    return render_template("forgot.html")



@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    data = session.get("reset")

    if not data:
        flash("Please request a new verification code.", "error")
        return redirect(url_for("forgot"))

    if time.time() > data["expiry"]:
        session.pop("reset", None)
        flash("Code has expired! Please request a new one.", "error")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        otp = request.form.get("otp", "").strip()

        attempts = data.get("attempts", 0)

        if attempts >= MAX_ATTEMPTS:
            session.pop("reset", None)
            flash("Too many attempts. Request a new code.", "error")
            return redirect(url_for("forgot"))

        data["attempts"] = attempts + 1
        session["reset"] = data

        if not (len(otp) == 6 and otp.isdigit()):
            flash("Invalid code.", "error")
            return redirect(url_for("verify_otp"))

        submitted_hash = hash_otp(otp)

        if hmac.compare_digest(submitted_hash, data["otp_hash"]):
            data["verified"] = True
            session["reset"] = data
            return redirect(url_for("reset"))

        if data["attempts"] >= MAX_ATTEMPTS:
            session.pop("reset", None)
            flash("Too many attempts. Request a new code.", "error")
            return redirect(url_for("forgot"))

        flash("Invalid code.", "error")
        return redirect(url_for("verify_otp"))

    return render_template("verify_otp.html")


@app.route("/welcomeback")
def welcomeback():
    return render_template("welcomeback.html", username=session["username"])


@app.route("/submit")
def submit():
    return render_template("submit.html")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    data = session.get("reset")

    if not data or not data.get("verified"):
        flash("Please verify your OTP first.", "error")
        return redirect(url_for("forgot"))

    if time.time() > data["expiry"]:
        session.pop("reset", None)
        flash("Code has expired!", "error")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        password = request.form["password"]
        confirm = request.form["confirm_password"]

        if password != confirm:
            flash("Passwords do not match!", "error")
            return redirect(url_for("reset"))

        conn = getdb()
        cursor = conn.cursor()

        try:
            cursor.execute(
                "UPDATE users SET password_hash = %s WHERE email = %s",
                (
                    generate_password_hash(password),
                    data["email"]
                )
            )
            conn.commit()
        finally:
            cursor.close()
            conn.close()

        session.pop("reset", None)
        flash("Password updated. Please log in!", "success")
        return redirect(url_for("login"))

    return render_template("reset.html")

if __name__== "__main__":
    app.run(debug=True)