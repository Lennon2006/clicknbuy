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
from alembic import op
import sqlalchemy as sa

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))

# --- Configuration ---
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'ads.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.environ.get('SECRET_KEY') or 'replace_with_a_strong_random_secret_key'

# Initialize DB with the Flask app
db.init_app(app)
migrate = Migrate(app, db)

with app.app_context():
    db.create_all()
    print("Total users:", User.query.count())

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

        print(f"DEBUG: Logged in as {user.username}, admin status: {user.is_admin}")  # Debug

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
    while True:
        with app.app_context():
            now = datetime.utcnow()
            expired_ads = Ad.query.filter(Ad.is_featured == True, Ad.feature_expiry < now).all()
            for ad in expired_ads:
                ad.is_featured = False
            if expired_ads:
                db.session.commit()
        time.sleep(3600)  # check every hour

def upgrade():
    op.add_column('user', sa.Column('is_verified', sa.Boolean(), nullable=True, server_default=sa.false()))
    op.alter_column('user', 'is_verified', nullable=False, server_default=None)

def downgrade():
    op.drop_column('user', 'is_verified')

# Routes
@app.route('/')
def home():
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

        if user and user.check_password(password):
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

#Profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get_or_404(int(session['user_id']))

    if request.method == 'POST':
        file = request.files.get('profile_pic')
        if file and allowed_file(file.filename):
            # Delete old pic if it exists and is not the default
            if user.profile_pic and user.profile_pic != 'default-profile.png':
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_pic)
                if os.path.exists(old_path):
                    try:
                        os.remove(old_path)
                    except Exception as e:
                        print(f"Error deleting old profile pic: {e}")

            # Save new profile picture
            filename = save_profile_pic(file)
            if filename:
                user.profile_pic = filename
                try:
                    db.session.commit()
                    flash("Profile picture updated.", "success")
                except Exception as e:
                    db.session.rollback()
                    flash("Failed to update profile picture in database.", "danger")
                    print(f"DB commit error: {e}")
            else:
                flash("Failed to save profile picture.", "danger")
        else:
            flash("Invalid file or no file selected.", "warning")
        return redirect(url_for('profile'))

    user_ratings = Rating.query.filter_by(reviewed_id=user.id).order_by(Rating.timestamp.desc()).all()
    return render_template('profile.html', user=user, user_ratings=user_ratings)



@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user = User.query.get_or_404(int(session['user_id']))

    if request.method == 'POST':
        new_username = request.form.get('username', '').strip()
        new_email = request.form.get('email', '').strip()
        new_password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

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


#ADS
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

    # Show featured ads first, then order all by newest
    ads = ads.order_by(Ad.is_featured.desc(), Ad.created_at.desc())

    # Get distinct categories for dropdown
    all_categories = db.session.query(Ad.category).distinct().all()
    categories = sorted(set(cat for (cat,) in all_categories if cat))

    return render_template('ads.html', ads=ads.all(), categories=categories)



#POST
@app.route('/post', methods=['GET', 'POST'])
@login_required
def post_ad():
    if request.method == 'POST':
        # Create new ad from form data
        new_ad = Ad(
            title=request.form['title'],
            description=request.form['description'],
            price=request.form['price'],
            category=request.form['category'],
            contact=request.form['contact'],
            location=request.form['location'],
            user_id=int(session['user_id'])
        )
        
        try:
            # Save the ad first
            db.session.add(new_ad)
            db.session.commit()

            # Save uploaded images
            images = request.files.getlist('images')
            for image in images:
                if image and allowed_file(image.filename):
                    filename = secure_filename(image.filename)
                    unique_name = f"user_{session['user_id']}_{uuid.uuid4().hex}_{filename}"
                    path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                    image.save(path)

                    # Save image record linked to the ad
                    db.session.add(Image(filename=unique_name, ad_id=new_ad.id))

            db.session.commit()  # Commit all images in one go
            log_activity(session['user_id'], "Posted an ad")
            flash("Ad posted successfully.", "success")
            return redirect(url_for('show_ads'))

        except Exception as e:
            db.session.rollback()
            flash("Something went wrong while posting your ad.", "danger")
            print(f"Error posting ad: {e}")

    return render_template('post.html')


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

    return render_template('edit.html', ad=ad)

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
    ads = Ad.query.order_by(Ad.is_featured.desc(), Ad.created_at.desc()).all()

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

# Public profile route by username
@app.route('/user/<username>')
def profile_public(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found.", "error")
        return redirect(url_for('home'))

    # Get ads posted by user to show on public profile
    ads = Ad.query.filter_by(user_id=user.id).order_by(Ad.id.desc()).all()

    # Get user ratings
    user_ratings = Rating.query.filter_by(reviewed_id=user.id).order_by(Rating.timestamp.desc()).all()
    return render_template('profile_public.html', user=user, ads=ads, ratings=user_ratings)

@app.route('/inbox')
@login_required
def inbox():
    user_id = int(session['user_id'])
    conversations = Conversation.query.filter(
        (Conversation.buyer_id == user_id) | (Conversation.seller_id == user_id)
    ).order_by(Conversation.id.desc()).all()

    unread_counts = {}
    for convo in conversations:
        count = Message.query.filter(
            Message.conversation_id == convo.id,
            Message.is_read == False,
            Message.sender_id != user_id
        ).count()
        unread_counts[convo.id] = count

    return render_template('inbox.html', conversations=conversations, unread_counts=unread_counts)




# API for editing messages
@app.route('/edit_message/<int:message_id>', methods=['POST'])
@login_required
def edit_message(message_id):
    msg = Message.query.get_or_404(message_id)
    if msg.sender_id != session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 403
    msg.content = request.json.get('content', '')
    db.session.commit()
    return jsonify({'success': True})

# API for deleting messages
@app.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    msg = Message.query.get_or_404(message_id)
    if msg.sender_id != session.get('user_id'):
        return jsonify({'error': 'Unauthorized'}), 403
    db.session.delete(msg)
    db.session.commit()
    return jsonify({'success': True})

# Payment features
#Feature AD
@app.route('/feature_ad/<int:ad_id>', methods=['POST'])
@login_required
def feature_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)

    # Only admin or Lennon can feature ads — optional
    if session.get('user_id') != 1:  # If Lennon is user_id 1
        abort(403)

    ad.is_featured = True
    ad.feature_expiry = datetime.utcnow() + timedelta(days=7)  # optional expiry logic
    db.session.commit()

    flash("Ad has been featured!", "success")
    return redirect(url_for('show_ads'))


@app.route('/admin/feature-requests')
@admin_required
def admin_feature_requests():
    pending_ads = Ad.query.filter_by(is_featured=True).order_by(Ad.feature_expiry.desc()).all()
    return render_template('admin_feature_requests.html', ads=pending_ads)

@app.route('/admin/confirm-payment/<int:ad_id>', methods=['POST'])
@admin_required
def confirm_feature_payment(ad_id):
    ad = Ad.query.get_or_404(ad_id)
    ad.is_paid = True
    db.session.commit()
    flash(f"Payment confirmed for ad '{ad.title}'", "success")
    return redirect(url_for('admin_feature_requests'))

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.id.desc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f"Deleted user {user.username}", "danger")
    return redirect(url_for('admin_users'))

@app.route('/admin/verify-user/<int:user_id>', methods=['POST'])
@admin_required
def admin_verify_user(user_id):
    user = User.query.get_or_404(user_id)
    user.is_verified = True
    db.session.commit()
    flash(f"Verified {user.username}", "success")
    return redirect(url_for('admin_users'))


if __name__ == '__main__':
    Thread(target=unfeature_expired_ads, daemon=True).start()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
