from flask import Flask,render_template,redirect,request,url_for,flash,session
import mysql.connector,secrets,time,smtplib,hashlib,os,hmac
from email.message import EmailMessage
from werkzeug.security import generate_password_hash,check_password_hash

app=Flask(__name__)

# Set SECRET_KEY in Vercel -> Settings -> Environment Variables.
# Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
app.secret_key=os.environ["SECRET_KEY"]


def getdb():
    return mysql.connector.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"],
        ssl_ca=os.path.join(os.path.dirname(__file__), "ca.pem"),
        ssl_verify_cert=True,
        ssl_verify_identity=True,
        use_pure=True,
        connection_timeout=5      # fail fast instead of hanging until Vercel kills the function
    )


@app.errorhandler(mysql.connector.Error)
def handle_db_error(e):
    # Any database failure (connection refused, too many connections, timeout...)
    app.logger.error("Database error: %s", e)
    return "Service temporarily unavailable. Please try again in a moment.", 503


@app.route("/favicon.ico")
def favicon():
    return "", 204


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
        username=request.form.get("username","").strip()
        email=request.form.get("email","").strip()
        password=request.form.get("password","")
        confirm=request.form.get("confirm_password","")

        if not username or not email or not password:
            flash("⚠️ Please fill in all fields.","error")
            return redirect(url_for("signup"))

        if len(username)>50 or len(email)>120:
            flash("⚠️ Username or email is too long.","error")
            return redirect(url_for("signup"))

        if password!=confirm:
            flash("⚠️ Passwords do not match!","error")
            return redirect(url_for("signup"))

        conn=getdb()
        cursor=conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO users(username,email,password_hash) VALUES (%s,%s,%s)",
                (username,email,generate_password_hash(password))
            )
            conn.commit()

        except mysql.connector.IntegrityError:
            flash("Username or Email already exists.","error")
            return redirect(url_for("signup"))

        finally:
            cursor.close()
            conn.close()

        session["new_user"]=username
        return redirect(url_for("submit"))

    return render_template("index.html")


@app.route("/login",methods=['GET','POST'])
def login():
    if request.method=='POST':
        identifier=request.form.get('login',"").strip()
        password=request.form.get('password',"")

        if not identifier or not password:
            flash("⚠️ Invalid Credentials","error")
            return redirect(url_for("login"))

        conn=getdb()
        cursor=conn.cursor(dictionary=True,buffered=True)   # buffered avoids "Unread result found"

        try:
            cursor.execute(
                "SELECT * FROM users WHERE email=%s or username=%s",
                (identifier,identifier)
            )

            user=cursor.fetchone()

            if user and check_password_hash(user["password_hash"],password):
                session["user_id"]=user["id"]
                session["username"]=user["username"]
                return redirect(url_for("welcomeback"))

            flash("⚠️ Invalid Credentials","error")
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
    msg.set_content(f"Your Verification Code is {otp}. It will expire in {OTP_TTL//60} minutes!")
    with smtplib.SMTP_SSL("smtp.gmail.com",465,timeout=10) as server:   # timeout prevents hanging
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
        cursor = conn.cursor(dictionary=True,buffered=True)

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
            flash("⚠️ Email is not registered!", "info")
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
            app.logger.error("Email error: %s", e)
            session.pop("reset", None)
            flash("Unable to send code. Please try again.", "error")
            return redirect(url_for("forgot"))

        flash("Verification Code has been sent.", "info")
        return redirect(url_for("verify_otp"))

    return render_template("forgot.html")


@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    data = session.get("reset")

    if not data:
        flash("Please request a new verification code.", "error")
        return redirect(url_for("forgot"))

    if time.time() > data.get("expiry", 0):
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
    username = session.get("username")
    if not username:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    return render_template("welcomeback.html", username=username)


@app.route("/submit")
def submit():
    return render_template("submit.html")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    data = session.get("reset")

    if not data or not data.get("verified"):
        flash("Please verify your OTP first.", "error")
        return redirect(url_for("forgot"))

    if time.time() > data.get("expiry", 0):
        session.pop("reset", None)
        flash("Code has expired!", "error")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not password:
            flash("Please enter a new password.", "error")
            return redirect(url_for("reset"))

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


if __name__ == "__main__":
    app.run(debug=False)