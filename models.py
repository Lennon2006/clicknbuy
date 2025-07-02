from datetime import datetime
from sqlalchemy.sql import func
from extensions import db  # import shared db instance

# ------------------ USER MODEL ------------------ #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=True)
    auth_provider = db.Column(db.String(50), default='local')
    profile_pic = db.Column(
        db.String(255),
        nullable=False,
        default='https://res.cloudinary.com/dlsx5lfex/image/upload/v1751135009/default-profile.jpg'
    )
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_verified = db.Column(db.Boolean, default=False)
    bio = db.Column(db.Text, nullable=True, default="")

    # Relationships
    activity_logs = db.relationship(
        'ActivityLog',
        back_populates='user',
        passive_deletes=True,
        cascade='all, delete-orphan',
        lazy=True
    )

    ads = db.relationship('Ad', backref='owner', lazy=True, cascade='all, delete-orphan')

    sent_conversations = db.relationship(
        'Conversation',
        foreign_keys='Conversation.seller_id',
        backref='seller',
        lazy=True,
        cascade='all, delete-orphan'
    )

    received_conversations = db.relationship(
        'Conversation',
        foreign_keys='Conversation.buyer_id',
        backref='buyer',
        lazy=True,
        cascade='all, delete-orphan'
    )

    ratings_given = db.relationship(
        'Rating',
        foreign_keys='Rating.reviewer_id',
        backref='reviewer',
        lazy=True,
        cascade='all, delete-orphan'
    )

    ratings_received = db.relationship(
        'Rating',
        foreign_keys='Rating.reviewed_id',
        backref='reviewed',
        lazy=True,
        cascade='all, delete-orphan'
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
    
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.String(50), nullable=False)
    post_type = db.Column(db.String(20), nullable=False, default='For Sale')
    category = db.Column(db.String(50), nullable=False)
    subcategory = db.Column(db.String(50), nullable=True)
    
    contact = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

    is_sold = db.Column(db.Boolean, default=False)
    is_paid = db.Column(db.Boolean, default=False)
    is_featured = db.Column(db.Boolean, default=False, index=True)
    feature_expiry = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, index=True)
    cdtimestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    images = db.relationship('Image', backref='ad', lazy=True, cascade="all, delete-orphan")
    conversations = db.relationship('Conversation', backref='ad', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Ad {self.title}>"


# ------------------ IMAGE MODEL ------------------ #
class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    url = db.Column(db.String(500))
    ad_id = db.Column(db.Integer, db.ForeignKey('ad.id', ondelete='CASCADE'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------ RATING MODEL ------------------ #
class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reviewer_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    reviewed_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    ad_id = db.Column(db.Integer, db.ForeignKey('ad.id', ondelete='CASCADE'), nullable=False)
    stars = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------ ACTIVITY LOG MODEL ------------------ #
class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    ip_address = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='activity_logs')


# ------------------ CONVERSATION MODEL ------------------ #
class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    ad_id = db.Column(db.Integer, db.ForeignKey('ad.id', ondelete='CASCADE'), nullable=False)

    messages = db.relationship('Message', backref='conversation', lazy=True, cascade='all, delete-orphan')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ------------------ MESSAGE MODEL ------------------ #
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id', ondelete='CASCADE'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    sender = db.relationship('User')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
