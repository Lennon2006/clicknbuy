from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    # Dummy ads list for testing
    latest_ads = [
        {'id': 1, 'title': 'Test Ad 1', 'price': 100, 'image_url': 'https://via.placeholder.com/300x180?text=Ad+1'},
        {'id': 2, 'title': 'Test Ad 2', 'price': 250, 'image_url': 'https://via.placeholder.com/300x180?text=Ad+2'},
        {'id': 3, 'title': 'Test Ad 3', 'price': 75,  'image_url': 'https://via.placeholder.com/300x180?text=Ad+3'},
        {'id': 4, 'title': 'Test Ad 4', 'price': 50,  'image_url': 'https://via.placeholder.com/300x180?text=Ad+4'},
    ]
    return render_template('home.html', latest_ads=latest_ads)

if __name__ == '__main__':
    app.run(debug=True)
