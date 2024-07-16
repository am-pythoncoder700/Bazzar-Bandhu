from flask import Flask, render_template, redirect, url_for, request, session
from validate_email import validate_email
import dns.resolver
from werkzeug.security import check_password_hash, generate_password_hash
import json
import pandas as pd
from flask_mail import Mail, Message
import re

app = Flask(__name__)
app.secret_key = "@ radha _ 78956 is the secret key *@"
mail = Mail(app)
allowed_extension = ["csv", "xlsx", "xls"]

with open('config.json', 'r') as f:
    params = json.load(f)['params']

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465  # Correct port for SSL
app.config['MAIL_USERNAME'] = params['gmail-user']
app.config['MAIL_PASSWORD'] = params['gmail-password']
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

# Initialize mail
mail = Mail(app)

# creating a dataframe of users_info
df_users = pd.read_excel('users_info.xlsx')

# creating a dataframe to see logged in users
df_log = pd.read_excel('logged_users.xlsx')

def send_welcome_email():
    try:
        # Send the welcome email to the user's email
        msg = Message('Welcome to Bazzar Bandhu', sender=app.config['MAIL_USERNAME'], recipients=[session['email']])
        msg.body = '''Thank you for registering on our website Bazzar Bandhu.
                      Team Bazzar Bandhu'''
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")

# email validation
def email_validate(email_id):
    # checking whether the email format is correct or not
    email_format = validate_email(email_id)
    if not email_format:
        return "Invalid Email Format"

    # checking whether the domain of email is valid or not
    try:
        domain = email_id.split("@")[1]
        dns.resolver.resolve(domain, "MX")
        domain_valid = True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        domain_valid = False

    if not domain_valid:
        return "Invalid Domain"
    return None

# password validation
def password_validate(password):
    pattern = r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"
    return bool(re.match(pattern, password))

@app.route("/index", methods = ["GET"])
def index():
    if session.get('is_logged') and request.method == "GET":
        return render_template("index.html")
    else:
        return redirect(url_for("signin"))

@app.route("/", methods=['GET', 'POST'])
def signin():
    global df_log
    global df_users
    if request.method == "GET":
        return render_template("signin.html")
    
    if request.method == "POST":
        username = request.form['email']
        password = request.form['password']

        # Email Validation
        error = email_validate(username)
        if error:
            return render_template("signin.html", error=error)

        # Check whether the username exists in our database or not
        if username in df_users['email_id'].values:
            # Check whether the password is correct or not
            stored_password = df_users.loc[df_users['email_id'] == username, 'password'].values[0]
            if check_password_hash(stored_password, password):
                session["email"] = username
                session['is_logged'] = True

                matched_row_number = df_users[df_users['email_id'] == username].index[0]
                name = df_users.iloc[matched_row_number, df_users.columns.get_loc('name')]

                logged_data = {
                    'name' : name,
                    'username' : username
                }

                df_log = df_log._append(logged_data, ignore_index = True)
                df_log.to_excel('logged_users.xlsx', index=False)
                return render_template("index.html", success=True)
            else:
                return render_template('signin.html', error="Invalid Password")
        else:
            return render_template("signup.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    global df_users
    if request.method == "GET":
        return render_template("signup.html")
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        # recovery_email = request.form['recovery_email']        

        if password_validate(password):
            # Hashing the password
            hashed_password = generate_password_hash(password)

            new_data = {
                'name': name,
                'email_id': email,
                'password': hashed_password,
            }

            if email not in df_users['email_id'].values:
                df_users = df_users._append(new_data, ignore_index=True)
                df_users.to_excel('users_info.xlsx', index=False)
                
                session['email'] = email
                session['is_logged'] = True
                send_welcome_email()
                return redirect(url_for("index"))
            else:
                return render_template('signin.html', error = 'present')
        else:
            return render_template('signup.html', error = True)

@app.route("/upload", methods=["GET"]) 
def upload():
    if session.get('is_logged'):
        return render_template("upload.html")
    else:
        return redirect(url_for("signin"))

@app.route("/dashboard", methods=["GET", "POST"]) 
def dashboard():
    if session['is_logged']:
        return render_template("dashboard.html")
    else:
        return redirect(url_for("signin"))
    
@app.route("/logout")
def logout():
    global df_log
    if session.get('is_logged'):
        email = session.get('email')
        df_log = df_log.drop(df_log[df_log['username'] == email].index)
        df_log.to_excel('logged_users.xlsx', index = False)
        session.clear()
        return render_template("logout.html", logout=True)
    
@app.route("/forget_password", methods = ["GET", "POST"])
def forget_password():
    global df_users
    if request.method == "GET" and not 'email' in session:
        return render_template('forget_password.html')
    else:
        email = request.form['email']
        password = request.form['password']
        
        if password_validate(password):
            matched_row_number = df_users[df_users['email_id'] == email].index[0]
            df_users.loc[matched_row_number, 'password'] = generate_password_hash(password)

            df_users.to_excel('users_info.xlsx', index = False)
            return redirect(url_for('signin'))
        else:
            return render_template('forget_password.html', error = True)
        
@app.route("/success", methods = ["POST"])
def success():
    global df_users
    if session.get('is_logged'):
        try:
            f = request.files['file']
            if f.filename.split(".")[1].lower() in allowed_extension:
                f.save('user_imp_files/' + f.filename)
                matched_row_number = df_users[df_users['email_id'] == session.get('email')].index[0]
                df_users.loc[matched_row_number, 'filename'] = f.filename
                df_users.to_excel('users_info.xlsx', index = False)
                return redirect(url_for("upload_success"))
        except:
            return redirect(url_for("upload_fail"))
        else:
            return redirect(url_for("upload_fail"))
    else:
        return redirect('signin')

@app.route("/upload_success")
def upload_success():
    return render_template("upload.html", message='success')

@app.route("/upload_fail")
def upload_fail():
    return render_template("upload.html", message='fail')


if __name__ == "__main__":
    app.run(debug=True)