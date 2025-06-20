from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate  # <-- Import Flask-Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import time 
import uuid  # for generating unique filenames



app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# Config
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'ads.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'replace_this_with_a_strong_random_secret_key'

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # <-- Initialize Flask-Migrate

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    profile_pic = db.Column(db.String(120), nullable=True)  # New field for profile picture filename
    ads = db.relationship('Ad', backref='owner', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Ad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    price = db.Column(db.String(50))
    category = db.Column(db.String(50))
    contact = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    images = db.relationship('Image', backref='ad', lazy=True, cascade="all, delete-orphan")

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    ad_id = db.Column(db.Integer, db.ForeignKey('ad.id'), nullable=False)

with app.app_context():
    db.create_all()

# Helpers
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def save_profile_pic(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # To avoid name collisions, you can prefix with user ID or a timestamp
        filename = f"user_{session['user_id']}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename
    return None

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm = request.form['confirm_password']

        if not all([username, email, password, confirm]):
            flash("All fields required.", "danger")
            return redirect(url_for('register'))
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash("Username exists.", "danger")
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("Email already used.", "danger")
            return redirect(url_for('register'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('username_or_email')
        password = request.form.get('password')

        if not identifier or not password:
            flash("Both fields are required.", "warning")
            return redirect(url_for('login'))

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash("Welcome back!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid login details.", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

import time  # Add this import at the top of your app.py

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post_ad():
    if request.method == 'POST':
        new_ad = Ad(
            title=request.form['title'],
            description=request.form['description'],
            price=request.form['price'],
            category=request.form['category'],
            contact=request.form['contact'],
            user_id=session['user_id']
        )
        db.session.add(new_ad)
        db.session.commit()

        for image in request.files.getlist('images'):
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                unique_name = f"user_{session['user_id']}_{uuid.uuid4().hex}_{filename}"
                path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                image.save(path)
                db.session.add(Image(filename=unique_name, ad_id=new_ad.id))

        db.session.commit()
        flash("Ad posted successfully.", "success")
        return redirect(url_for('show_ads'))

    return render_template('post.html')



@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        # Handle profile picture upload
        file = request.files.get('profile_pic')
        if file and allowed_file(file.filename):
            # Delete old profile pic if exists
            if user.profile_pic:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_pic)
                if os.path.exists(old_path):
                    os.remove(old_path)
            # Save new profile pic
            filename = save_profile_pic(file)
            user.profile_pic = filename
            db.session.commit()
            flash("Profile picture updated.", "success")
        else:
            flash("Invalid file or no file selected.", "warning")
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)


@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        new_username = request.form.get('username').strip()
        new_email = request.form.get('email').strip()
        new_password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not new_username or not new_email:
            flash("Username and email are required.", "danger")
            return redirect(url_for('edit_profile'))

        if new_username != user.username and User.query.filter_by(username=new_username).first():
            flash("Username already taken.", "danger")
            return redirect(url_for('edit_profile'))

        if new_email != user.email and User.query.filter_by(email=new_email).first():
            flash("Email already in use.", "danger")
            return redirect(url_for('edit_profile'))

        user.username = new_username
        user.email = new_email

        if new_password:
            if new_password != confirm_password:
                flash("Passwords do not match.", "danger")
                return redirect(url_for('edit_profile'))
            user.set_password(new_password)

        db.session.commit()
        session['username'] = user.username
        flash("Profile updated successfully.", "success")
        return redirect(url_for('profile'))

    return render_template('edit_profile.html', user=user)


@app.route('/ads')
def show_ads():
    ads = Ad.query.all()
    return render_template('ads.html', ads=ads)

@app.route('/edit/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def edit_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    if ad.user_id != session['user_id']:
        flash("You do not have permission to edit this ad.", "danger")
        return redirect(url_for('show_ads'))

    if request.method == 'POST':
        ad.title = request.form['title']
        ad.description = request.form['description']
        ad.price = request.form['price']
        ad.category = request.form['category']
        ad.contact = request.form['contact']

        # Delete selected images
        delete_ids = request.form.getlist('delete_images')
        for img_id in delete_ids:
            img = Image.query.get(int(img_id))
            if img and img.ad_id == ad.id:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], img.filename))
                except:
                    pass
                db.session.delete(img)

        # Add new uploaded images
        for image in request.files.getlist('images'):
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                unique_name = f"user_{session['user_id']}_{uuid.uuid4().hex}_{filename}"
                path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                image.save(path)
                db.session.add(Image(filename=unique_name, ad_id=ad.id))

        db.session.commit()
        flash("Ad updated.", "success")
        return redirect(url_for('show_ads'))

    return render_template('edit.html', ad=ad)

@app.route('/delete/<int:ad_id>', methods=['POST'])
@login_required
def delete_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    if ad.user_id != session['user_id']:
        flash("You do not have permission to delete this ad.", "danger")
        return redirect(url_for('show_ads'))

    for img in ad.images:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], img.filename))
        except:
            pass

    db.session.delete(ad)
    db.session.commit()
    flash("Ad deleted.", "info")
    return redirect(url_for('show_ads'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
