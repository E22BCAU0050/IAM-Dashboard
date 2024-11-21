from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import boto3
import datetime

app = Flask(__name__)
app.secret_key = "dev_secret_key"

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///iam_dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# AWS IAM client
iam_client = boto3.client('iam')

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resource = db.Column(db.String(120), nullable=False)
    access_key_id = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(10), default="Pending")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('tickets', lazy=True))
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            flash("Login successful!", "success")
            return redirect(url_for('admin_dashboard' if user.is_admin else 'dashboard'))
        flash("Invalid credentials!", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check for existing user
        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, email=email, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        flash("User registered successfully!", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        flash("You must be logged in to access this page!", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        resource = request.form['resource']
        access_key_id = request.form['access_key_id']
        ticket = Ticket(resource=resource, access_key_id=access_key_id, user_id=session['user_id'])
        db.session.add(ticket)
        db.session.commit()
        flash("Ticket created successfully!", "success")
        return redirect(url_for('dashboard'))
    
    tickets = Ticket.query.filter_by(user_id=session['user_id']).all()
    return render_template('dashboard.html', tickets=tickets)

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session:
        flash("You must be logged in to access this page!", "danger")
        return redirect(url_for('login'))

    if not session.get('is_admin', False):
        flash("You don't have permission to access this page!", "danger")
        return redirect(url_for('dashboard'))

    # Fetch logged-in user's details
    user = User.query.get(session['user_id'])
    session['username'] = user.username  # Set the username in session

    pending_tickets = Ticket.query.filter_by(status="Pending").all()
    completed_tickets = Ticket.query.filter(Ticket.status != "Pending").all()
    
    iam_groups_response = iam_client.list_groups()  # You can keep this if you still want to display IAM groups
    iam_groups = iam_groups_response.get('Groups', [])

    if request.method == 'POST':
        ticket_id = request.form['ticket_id']
        action = request.form['action']

        ticket = Ticket.query.get(ticket_id)

        if action == "reject":
            ticket.status = "Rejected"
            flash(f"Ticket {ticket.id} has been rejected.", "danger")

        elif action == "approve":
            # Approve logic: Update status to 'Approved' without interacting with AWS
            ticket.status = "Approved"
            flash(f"Ticket {ticket.id} approved.", "success")

        db.session.commit()

    # Pass the username for each ticket to the template
    return render_template('admin_dashboard.html', 
                           pending_tickets=pending_tickets, 
                           completed_tickets=completed_tickets, 
                           iam_groups=iam_groups,
                           get_username=lambda user_id: User.query.get(user_id).username)  # Helper function for fetching username

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", password=generate_password_hash("admin"), email="admin@example.com", is_admin=True)
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True, host="0.0.0.0")