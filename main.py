from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
db = SQLAlchemy()
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
session = db.session

login_manager = LoginManager()
login_manager.init_app(app)

##CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB.
# db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return session.get(entity=User, ident=int(user_id))

with app.app_context():
    # db.session.query(User).delete()
    # db.session.commit()
    @app.route('/')
    def home():
        return render_template("index.html", user=current_user)


    @app.route('/register', methods=["GET", "POST"])
    def register():
        if request.method == 'POST':
            user = User.query.filter_by(email=request.form.get('email')).first()
            if user:
                flash(message='You\'ve already registered. Login instead', category='error')
                return redirect(url_for('login'))
            else:
                password = request.form.get('password')
                add_user = User(
                    name=request.form.get('name'),
                    email=request.form.get('email'),
                    password=generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)
                )
                session.add(add_user)
                session.commit()
                return render_template("secrets.html", name=request.form.get('name'), user=current_user)
        return render_template("register.html", user=current_user)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            user = User.query.filter_by(email=request.form.get('email')).first()
            if user:
                if check_password_hash(pwhash=user.password, password=request.form.get('password')):
                    login_user(user)
                    return redirect(url_for('secrets', name=user.name))
                else:
                    flash(message='Password is incorrect', category='error')
            else:
                flash(message='Email does\'nt exist. You can register for a new account', category='error')
        return render_template("login.html", user=current_user)


    @app.route('/secrets', methods=["GET"])
    @login_required
    def secrets():
        return render_template("secrets.html", user=current_user, name=request.args.get('name'))


    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('home'))


    @app.route('/download')
    @login_required
    def download():
        return send_from_directory(
            # app.config['UPLOAD_FOLDER'], as_attachment=True,
            directory='./static',
            path='./files/cheat_sheet.pdf'
        )


    if __name__ == "__main__":
        app.run(debug=True)
