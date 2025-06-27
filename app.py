from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, abort
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import uuid
from datetime import datetime, timedelta
from threading import Thread
import time
from models import db, User, Ad, Image, Rating, ActivityLog, Conversation, Message
import json
from sqlalchemy import or_, and_
from flask_socketio import SocketIO, emit
from flask_login import current_user



app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

socketio = SocketIO(app)

# Load categories once at startup
basedir = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(basedir, 'data', 'categories.json')) as f:
    categories = json.load(f)

# Config
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'ads.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('SECRET_KEY') or 'replace_with_a_strong_random_secret_key'


# Initialize DB and migrations
db.init_app(app)
migrate = Migrate(app, db)

with app.app_context():
    db.create_all()
    print("Total users:", User.query.count())


# Decorator to restrict admin access
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            flash("Admin access required.", "danger")
            return redirect(url_for('login'))  # adjust if your login route is different
        return f(*args, **kwargs)
    return decorated_function

# Helper functions


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

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            flash("Please log in first.", "warning")
            return redirect(url_for('login'))

        user = User.query.get(user_id)
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for('login'))

        if not user.is_admin:
            return render_template("403.html"), 403

        return f(*args, **kwargs)
    return decorated_function

def save_profile_pic(file):
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filename = f"user_{session['user_id']}_{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return filename
    return None

def log_activity(user_id, action):
    ip = request.remote_addr
    log = ActivityLog(user_id=user_id, action=action, ip_address=ip)
    db.session.add(log)
    db.session.commit()

def unfeature_expired_ads():
    expired_ads = Ad.query.filter(
        Ad.is_featured == True,
        Ad.feature_expiry != None,
        Ad.feature_expiry < datetime.utcnow()
    ).all()

    for ad in expired_ads:
        ad.is_featured = False
        ad.feature_expiry = None

    if expired_ads:
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Unfeature error: {e}")

# Routes

@app.route('/')
def home():
    unfeature_expired_ads()  # ✅ cleanup expired featured ads
    latest_ads = Ad.query.order_by(Ad.id.desc()).limit(4).all()
    return render_template('home.html', latest_ads=latest_ads)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email already taken.", "danger")
            return redirect(url_for('register'))

        new_user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            profile_pic='default-profile.png'
        )

        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please login.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('username_or_email', '').strip()
        password = request.form.get('password', '')

        if not identifier or not password:
            flash("Both fields are required.", "warning")
            return redirect(url_for('login'))

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            log_activity(user.id, "Logged in")
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

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    unfeature_expired_ads()
    user = User.query.get_or_404(int(session['user_id']))
    updated = False
 
    if request.method == 'POST':
        # Handle Profile Picture Upload
        file = request.files.get('profile_pic')
        if file and allowed_file(file.filename):
            if user.profile_pic and user.profile_pic != 'default-profile.png':
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_pic)
                if os.path.exists(old_path):
                    try:
                        os.remove(old_path)
                    except Exception as e:
                        print(f"Error deleting old profile pic: {e}")

            filename = save_profile_pic(file)
            if filename:
                user.profile_pic = filename
                updated = True
            else:
                flash("Failed to save profile picture.", "danger")

        # Handle Bio Update
        bio = request.form.get('bio', '').strip()
        if bio != user.bio:
            user.bio = bio
            updated = True

        # Commit changes if any
        if updated:
            try:
                db.session.commit()
                flash("Profile updated successfully.", "success")
            except Exception as e:
                db.session.rollback()
                flash("Failed to update profile.", "danger")
                print(f"DB commit error: {e}")
        else:
            flash("No changes detected.", "info")

        return redirect(url_for('profile'))
        

    # On GET, load ratings and ads for display
    user_ratings = Rating.query.filter_by(reviewed_id=user.id).order_by(Rating.timestamp.desc()).all()
    ads = Ad.query.filter_by(user_id=user.id).order_by(Ad.id.desc()).all()
    return render_template('profile.html', user=user, user_ratings=user_ratings, ads=ads)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = User.query.get_or_404(int(session['user_id']))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        bio = request.form.get('bio', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        updated = False

        # Validate username uniqueness if changed
        if username != user.username:
            if User.query.filter_by(username=username).first():
                flash('Username already taken.', 'danger')
                return redirect(url_for('edit_profile'))
            user.username = username
            updated = True

        # Validate email uniqueness if changed
        if email != user.email:
            if User.query.filter_by(email=email).first():
                flash('Email already in use.', 'danger')
                return redirect(url_for('edit_profile'))
            user.email = email
            updated = True

        # Update bio
        if bio != user.bio:
            user.bio = bio
            updated = True

        # Handle password update
        if password:
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return redirect(url_for('edit_profile'))
            user.set_password(password)
            updated = True

        # Handle profile picture upload
        file = request.files.get('profile_pic')
        if file and allowed_file(file.filename):
            # Remove old pic if not default
            if user.profile_pic and user.profile_pic != 'default-profile.png':
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_pic)
                if os.path.exists(old_path):
                    try:
                        os.remove(old_path)
                    except Exception as e:
                        print(f"Error deleting old profile pic: {e}")

            filename = save_profile_pic(file)
            if filename:
                user.profile_pic = filename
                updated = True
            else:
                flash("Failed to save profile picture.", "danger")

        # Commit changes if anything updated
        if updated:
            try:
                db.session.commit()
                flash('Profile updated successfully.', 'success')
            except Exception as e:
                db.session.rollback()
                flash('Failed to update profile. Please try again.', 'danger')
                print(f"Error updating profile: {e}")
        else:
            flash('No changes detected.', 'info')

        return redirect(url_for('profile'))

    # GET request - render edit form
    return render_template('edit_profile.html', user=user)


@app.route('/verify_account', methods=['POST'])
@login_required
def verify_account():
    user = User.query.get_or_404(int(session['user_id']))

    if user.is_verified:
        flash("Your account is already verified.", "info")
        return redirect(url_for('profile'))

    # Skip payment, instantly verify
    user.is_verified = True
    try:
        db.session.commit()
        flash("Your account is now verified! (Free for now)", "success")
    except Exception as e:
        db.session.rollback()
        flash("Verification failed. Please try again.", "danger")
        print(f"Verification error: {e}")

    return redirect(url_for('profile'))



@app.route('/ads')
def show_ads():
    query = request.args.get('q', '').strip().lower()
    selected_category = request.args.get('category', '')

    ads = Ad.query

    if query:
        ads = ads.filter(
            (Ad.title.ilike(f"%{query}%")) |
            (Ad.description.ilike(f"%{query}%"))
        )
    if selected_category:
        ads = ads.filter_by(category=selected_category)

    ads = ads.order_by(Ad.is_featured.desc(), Ad.created_at.desc())

    # Pass the categories loaded from JSON
    return render_template('ads.html', ads=ads.all(), categories=categories)

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post_ad():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        price = request.form.get('price')
        category = request.form.get('category')
        subcategory = request.form.get('subcategory')
        post_type = request.form.get('post_type')
        contact = request.form.get('contact')
        location = request.form.get('location')
        user_id = int(session['user_id'])

        if not all([title, description, price, category, post_type, contact]):
            flash("Please fill out all required fields, including post type.", "danger")
            return redirect(url_for('post_ad'))

        new_ad = Ad(
            title=title,
            description=description,
            price=price,
            category=category,
            post_type=post_type,
            contact=contact,
            location=location,
            user_id=user_id,
            created_at=datetime.utcnow()
        )

        try:
            db.session.add(new_ad)
            db.session.commit()

            images = request.files.getlist('images')
            for image in images:
                if image and allowed_file(image.filename):
                    filename = secure_filename(image.filename)
                    unique_name = f"user_{user_id}_{uuid.uuid4().hex}_{filename}"
                    path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                    image.save(path)
                    db.session.add(Image(filename=unique_name, ad_id=new_ad.id))

            db.session.commit()
            log_activity(user_id, "Posted an ad")
            flash("Ad posted successfully.", "success")
            return redirect(url_for('show_ads'))

        except Exception as e:
            db.session.rollback()
            flash("Something went wrong while posting your ad.", "danger")
            print(f"Error posting ad: {e}")

    return render_template('post.html', categories=categories)

@app.route('/edit/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def edit_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    if ad.user_id != int(session['user_id']):
        flash("You do not have permission to edit this ad.", "danger")
        return redirect(url_for('show_ads'))

    if request.method == 'POST':
        ad.title = request.form['title']
        ad.description = request.form['description']
        ad.price = request.form['price']
        ad.category = request.form['category']
        ad.contact = request.form['contact']
        ad.location = request.form['location']

        delete_ids = request.form.getlist('delete_images')
        for img_id in delete_ids:
            img = Image.query.get(int(img_id))
            if img and img.ad_id == ad.id:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], img.filename))
                except Exception as e:
                    print(f"Error deleting image file: {e}")
                db.session.delete(img)

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

    return render_template('edit.html', ad=ad, categories=categories)

@app.route('/delete/<int:ad_id>', methods=['POST'])
@login_required
def delete_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    if ad.user_id != int(session['user_id']):
        flash("You do not have permission to delete this ad.", "danger")
        return redirect(url_for('show_ads'))

    for img in ad.images:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], img.filename))
        except Exception as e:
            print(f"Error deleting image file: {e}")

    db.session.delete(ad)
    db.session.commit()
    flash("Ad deleted.", "info")
    return redirect(url_for('show_ads'))

@app.route('/ads/<int:ad_id>', methods=['GET', 'POST'])
def ad_detail(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    user_id = session.get('user_id')

    seller = User.query.get(ad.user_id)
    seller_avg_rating = seller.average_rating() if seller else None

    ratings = Rating.query.filter_by(ad_id=ad.id).order_by(Rating.timestamp.desc()).all()

    if request.method == 'POST':
        if not user_id:
            flash("You must be logged in to submit a review.", "warning")
            return redirect(url_for('login'))

        stars = int(request.form.get('stars', 0))
        comment = request.form.get('comment', '').strip()

        if user_id == ad.user_id:
            flash("You cannot review your own ad.", "danger")
            return redirect(url_for('ad_detail', ad_id=ad_id))

        existing_rating = Rating.query.filter_by(ad_id=ad.id, reviewer_id=user_id).first()
        if existing_rating:
            flash("You have already reviewed this ad.", "warning")
            return redirect(url_for('ad_detail', ad_id=ad_id))

        if stars < 1 or stars > 5:
            flash("Invalid rating value.", "danger")
            return redirect(url_for('ad_detail', ad_id=ad_id))

        new_rating = Rating(
            reviewer_id=user_id,
            reviewed_id=ad.user_id,
            ad_id=ad.id,
            stars=stars,
            comment=comment if comment else None,
        )
        db.session.add(new_rating)
        db.session.commit()
        flash("Thank you for your review!", "success")
        return redirect(url_for('ad_detail', ad_id=ad_id))

    return render_template('ad_detail.html', ad=ad, seller_avg_rating=seller_avg_rating, ratings=ratings)

@app.route('/messages/<int:conversation_id>', methods=['GET', 'POST'])
@login_required
def messages(conversation_id):
    convo = Conversation.query.get_or_404(conversation_id)
    user_id = int(session['user_id'])
    if user_id not in [convo.buyer_id, convo.seller_id]:
        flash("Access denied.", "danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        content = request.form['content'].strip()
        if content:
            msg = Message(
                conversation_id=conversation_id,
                sender_id=user_id,
                content=content,
                is_read=True
            )
            db.session.add(msg)
            db.session.commit()
            return redirect(url_for('messages', conversation_id=conversation_id))

    unread_msgs = Message.query.filter(
        Message.conversation_id == conversation_id,
        Message.is_read == False,
        Message.sender_id != user_id
    ).all()
    for msg in unread_msgs:
        msg.is_read = True
    if unread_msgs:
        db.session.commit()

    messages_list = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp.asc()).all()
    return render_template('messages.html', conversation=convo, messages=messages_list)

@app.route('/start_conversation/<int:ad_id>', methods=['GET', 'POST'])
@login_required
def start_conversation(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    buyer_id = int(session['user_id'])
    seller_id = ad.user_id

    if buyer_id == seller_id:
        flash("You cannot message yourself.", "warning")
        return redirect(url_for('ad_detail', ad_id=ad_id))

    convo = Conversation.query.filter_by(ad_id=ad_id, buyer_id=buyer_id, seller_id=seller_id).first()
    if not convo:
        convo = Conversation(ad_id=ad_id, buyer_id=buyer_id, seller_id=seller_id)
        db.session.add(convo)
        db.session.commit()

    return redirect(url_for('messages', conversation_id=convo.id))

@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html"), 403

@app.route('/user/<username>')
def profile_public(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('home'))

    ads = Ad.query.filter_by(user_id=user.id).order_by(Ad.id.desc()).all()
    user_ratings = Rating.query.filter_by(reviewed_id=user.id).order_by(Rating.timestamp.desc()).all()

    avg_rating = user.average_rating() if user else None

    return render_template('profile_public.html', user=user, ads=ads, avg_rating=avg_rating, ratings=user_ratings)

# Run background thread for unfeaturing ads
def start_background_threads():
    thread = Thread(target=unfeature_expired_ads, daemon=True)
    thread.start()


#CONVOS
@app.route('/conversation/<int:conversation_id>', methods=['GET', 'POST'])
def conversation_detail(conversation_id):
    user_id = session.get('user_id')
    conv = Conversation.query.get_or_404(conversation_id)

    if user_id not in [conv.buyer_id, conv.seller_id]:
        abort(403)

    # Mark unread messages from other user as read
    unread_messages = Message.query.filter(
        Message.conversation_id == conv.id,
        Message.is_read == False,
        Message.sender_id != user_id
    ).all()
    for msg in unread_messages:
        msg.is_read = True
    db.session.commit()

    # Handle sending new message
    if request.method == 'POST' and 'new_message' in request.form:
        content = request.form.get('new_message', '').strip()
        if content:
            new_msg = Message(
                conversation_id=conv.id,
                sender_id=user_id,
                content=content,
                is_read=False,
                timestamp=datetime.utcnow()
            )
            db.session.add(new_msg)
            db.session.commit()
            return redirect(url_for('conversation_detail', conversation_id=conversation_id))

    # Handle deleting a message (via query param)
    delete_id = request.args.get('delete')
    if delete_id:
        msg_to_delete = Message.query.filter_by(
            id=delete_id,
            conversation_id=conv.id,
            sender_id=user_id
        ).first()
        if msg_to_delete:
            db.session.delete(msg_to_delete)
            db.session.commit()
            flash('Message deleted.', 'success')
            return redirect(url_for('conversation_detail', conversation_id=conversation_id))
        else:
            flash('Cannot delete message.', 'danger')

    # Handle editing a message (form submit with query param ?edit=msg_id)
    edit_id = request.args.get('edit')
    if edit_id and request.method == 'POST' and 'edit_message' in request.form:
        msg_to_edit = Message.query.filter_by(
            id=edit_id,
            conversation_id=conv.id,
            sender_id=user_id
        ).first()
        if msg_to_edit:
            new_content = request.form.get('edit_message', '').strip()
            if new_content:
                msg_to_edit.content = new_content
                db.session.commit()
                flash('Message updated.', 'success')
                return redirect(url_for('conversation_detail', conversation_id=conversation_id))
            else:
                flash('Message content cannot be empty.', 'warning')

    return render_template('conversation_detail.html', conversation=conv, user_id=user_id)


#SMS
@app.route('/inbox')
def inbox():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # Get conversations where user is buyer or seller
    conversations = Conversation.query.filter(
        or_(Conversation.buyer_id == user_id, Conversation.seller_id == user_id)
    ).all()

    # For each conversation, check for unread messages from the other user
    conv_with_unread = []
    for conv in conversations:
        unread_count = Message.query.filter(
            Message.conversation_id == conv.id,
            Message.is_read == False,
            Message.sender_id != user_id
        ).count()
        conv_with_unread.append((conv, unread_count > 0))

    return render_template('inbox.html', conversations=conv_with_unread)

#/feature/<int:ad_id
@app.route('/feature/<int:ad_id>', methods=['POST'])
@login_required
def feature_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)

    if ad.user_id != int(session['user_id']):
        flash("You are not authorized to feature this ad.", "danger")
        return redirect(url_for('ad_detail', ad_id=ad.id))

    if ad.is_sold:
        flash("Sold ads cannot be featured.", "warning")
        return redirect(url_for('ad_detail', ad_id=ad.id))

    if ad.is_featured:
        flash("This ad is already featured.", "info")
        return redirect(url_for('ad_detail', ad_id=ad.id))

    # Skip payment, instantly feature ad
    ad.is_featured = True
    ad.feature_expiry = datetime.utcnow() + timedelta(days=7)

    try:
        db.session.commit()
        flash("Your ad is now featured for 7 days! (Free for now)", "success")
    except Exception as e:
        db.session.rollback()
        flash("Failed to feature your ad. Please try again.", "danger")
        print(f"Feature error: {e}")

    return redirect(url_for('ad_detail', ad_id=ad.id))


#Terms and about
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

#Typing
@socketio.on('typing')
def handle_typing(data):
    emit('show_typing', data, broadcast=True)


# Show all users
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

# Delete a user
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == user.id:
        flash("You cannot delete your own account.", "warning")
        return redirect(url_for('admin_users'))
    db.session.delete(user)
    db.session.commit()
    flash(f"User {user.username} deleted.", "success")
    return redirect(url_for('admin_users'))

# Verify a user
@app.route('/admin/users/verify/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_verify_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_verified = True
    db.session.commit()
    flash(f"User {user.username} verified.", "success")
    return redirect(url_for('admin_users'))


if __name__ == '__main__':
    start_background_threads()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
