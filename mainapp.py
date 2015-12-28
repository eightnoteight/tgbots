from flask import Flask
from wordpress_com_bot import wpbotapp

app = Flask(__name__)
app.register_blueprint(wpbotapp, url_prefix='/wordpress_com_bot')

if __name__ == '__main__':
    app.run(debug=True)

