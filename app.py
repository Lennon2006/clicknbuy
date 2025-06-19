from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Base directory
basedir = os.path.abspath(os.path.dirname(__file__))

# Upload folder configuration
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure folder exists

# Allowed extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Database configuration
# Use environment variable for production DB path, fallback to local sqlite
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
    'sqlite:///' + os.path.join(basedir, 'ads.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class Ad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    price = db.Column(db.String(50))
    category = db.Column(db.String(50))
    contact = db.Column(db.String(100))
    images = db.relationship('Image', backref='ad', lazy=True, cascade="all, delete-orphan")

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    ad_id = db.Column(db.Integer, db.ForeignKey('ad.id'), nullable=False)

# Create DB tables if they don't exist
with app.app_context():
    db.create_all()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/post', methods=['GET', 'POST'])
def post_ad():
    if request.method == 'POST':
        new_ad = Ad(
            title=request.form['title'],
            description=request.form['description'],
            price=request.form['price'],
            category=request.form['category'],
            contact=request.form['contact']
        )
        db.session.add(new_ad)
        db.session.commit()

        images = request.files.getlist('images')
        for image in images:
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                new_image = Image(filename=filename, ad_id=new_ad.id)
                db.session.add(new_image)

        db.session.commit()
        return redirect(url_for('show_ads'))
    return render_template('post.html')

@app.route('/ads')
def show_ads():
    all_ads = Ad.query.all()
    return render_template('ads.html', ads=all_ads)

@app.route('/delete/<int:ad_id>', methods=['POST'])
def delete_ad(ad_id):
    ad_to_delete = Ad.query.get_or_404(ad_id)
    # Delete associated image files from filesystem
    for img in ad_to_delete.images:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], img.filename))
        except Exception:
            pass
    db.session.delete(ad_to_delete)
    db.session.commit()
    return redirect(url_for('show_ads'))

@app.route('/edit/<int:ad_id>', methods=['GET', 'POST'])
def edit_ad(ad_id):
    ad = Ad.query.get_or_404(ad_id)

    if request.method == 'POST':
        # Update ad fields
        ad.title = request.form['title']
        ad.description = request.form['description']
        ad.price = request.form['price']
        ad.category = request.form['category']
        ad.contact = request.form['contact']

        # Delete selected images
        delete_image_ids = request.form.getlist('delete_images')
        if delete_image_ids:
            for img_id in delete_image_ids:
                image = Image.query.get(int(img_id))
                if image:
                    # Remove image file from filesystem
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image.filename))
                    except Exception:
                        pass
                    # Delete image record
                    db.session.delete(image)

        # Add new uploaded images
        images = request.files.getlist('images')
        for image in images:
            if image and allowed_file(image.filename):
                filename = secure_filename(image.filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                new_image = Image(filename=filename, ad_id=ad.id)
                db.session.add(new_image)

        db.session.commit()
        return redirect(url_for('show_ads'))

    return render_template('edit.html', ad=ad)

if __name__ == '__main__':
    # Bind to 0.0.0.0 and use port from env var for Render compatibility
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
