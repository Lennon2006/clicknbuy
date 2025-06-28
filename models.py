from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import func



db = SQLAlchemy()

# ------------------ USER MODEL ------------------ #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)  # changed from nullable=False
    auth_provider = db.Column(db.String(50), default='local')  # NEW FIELD
    profile_pic = db.Column(db.String(255), nullable=False, default='default-profile.png')
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)
    bio = db.Column(db.Text, nullable=True, default="")

    ads = db.relationship('Ad', backref='owner', lazy=True)

    sent_conversations = db.relationship(
        'Conversation',
        foreign_keys='Conversation.seller_id',
        backref='seller',
        lazy=True
    )
    received_conversations = db.relationship(
        'Conversation',
        foreign_keys='Conversation.buyer_id',
        backref='buyer',
        lazy=True
    )

    activities = db.relationship('ActivityLog', backref='user', lazy=True)

    ratings_given = db.relationship(
        'Rating',
        foreign_keys='Rating.reviewer_id',
        backref='reviewer',
        lazy=True
    )
    ratings_received = db.relationship(
        'Rating',
        foreign_keys='Rating.reviewed_id',
        backref='reviewed',
        lazy=True
    )

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    def average_rating(self):
        if not self.ratings_received:
            return None
        return round(sum(r.stars for r in self.ratings_received) / len(self.ratings_received), 2)


# ------------------ AD MODEL ------------------ #

class Ad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    
    # Main ad content
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.String(50), nullable=False)
    post_type = db.Column(db.String(20), nullable=False, default='For Sale')
    category = db.Column(db.String(50), nullable=False)
    subcategory = db.Column(db.String(50), nullable=True)
    
    # User contact/location
    contact = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Status flags
    is_sold = db.Column(db.Boolean, default=False)
    is_paid = db.Column(db.Boolean, default=False)  # For future paid/boosted ad features
    is_featured = db.Column(db.Boolean, default=False, index=True)
    feature_expiry = db.Column(db.DateTime, nullable=True)

    # Timestamps
    created_at = db.Column(db.DateTime, index=True)
    cdtimestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    images = db.relationship('Image', backref='ad', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Ad {self.title}>"
    
    


# ------------------ IMAGE MODEL ------------------ #
class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))  # optional, you can keep it
    url = db.Column(db.String(500))       # <--- Add this for Cloudinary
    ad_id = db.Column(db.Integer, db.ForeignKey('ad.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------ RATING MODEL ------------------ #
class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reviewed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ad_id = db.Column(db.Integer, db.ForeignKey('ad.id'), nullable=False)
    stars = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------ ACTIVITY LOG MODEL ------------------ #
class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------ CONVERSATION MODEL ------------------ #
class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ad_id = db.Column(db.Integer, db.ForeignKey('ad.id'), nullable=False)

    messages = db.relationship('Message', backref='conversation', lazy=True, cascade='all, delete-orphan')
    ad = db.relationship('Ad')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------ MESSAGE MODEL ------------------ #
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    sender = db.relationship('User')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
