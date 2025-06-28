from app import app, db
from models import User


DEFAULT_LOCAL = 'default-profile.png'
DEFAULT_CLOUDINARY_URL = 'https://res.cloudinary.com/dlsx5lfex/image/upload/v1751135009/default-profile.jpg'

def update_default_profile_pics():
    users_to_update = User.query.filter(User.profile_pic == DEFAULT_LOCAL).all()
    count = 0
    for user in users_to_update:
        user.profile_pic = DEFAULT_CLOUDINARY_URL
        count += 1
    if count > 0:
        db.session.commit()
        print(f"Updated {count} users to use Cloudinary default profile picture.")
    else:
        print("No users needed updating.")

if __name__ == "__main__":
    update_default_profile_pics()
