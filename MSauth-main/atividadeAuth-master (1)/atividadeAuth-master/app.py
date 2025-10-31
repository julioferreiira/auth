from flask import Flask
from db import init_db
from auth_controller import auth_bp

app = Flask(__name__)


init_db()


app.register_blueprint(auth_bp)

if __name__ == "__main__":
    app.run(debug=True)

