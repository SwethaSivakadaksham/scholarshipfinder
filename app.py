from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ------------------------ USER MODEL ------------------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# ------------------------ ADMIN MODEL ------------------------

class Admin(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# ------------------------ SCHOLARSHIP MODEL ------------------------

class Scholarship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    income_limit = db.Column(db.Integer, nullable=False)
    percentage_required = db.Column(db.Integer, nullable=False)
    community = db.Column(db.String(100), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ------------------------ ROUTES ------------------------

@app.route('/')
def home():
    return render_template('index.html')

# ------------------------ USER AUTHENTICATION ------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        percentage = int(request.form['percentage'])
        community = request.form['community']

        eligible_scholarships = Scholarship.query.filter(
            Scholarship.percentage_required <= percentage,
            Scholarship.community == community
        ).all()

        return render_template('scholarships.html', scholarships=eligible_scholarships)

    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# ------------------------ ADMIN AUTHENTICATION ------------------------

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin = Admin.query.filter_by(username=request.form['username']).first()
        if admin and bcrypt.check_password_hash(admin.password, request.form['password']):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid login credentials.", "danger")
    return render_template('admin_login.html')

@app.route('/admin-logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# ------------------------ ADMIN PANEL ------------------------

@app.route('/admin-dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        flash("Please log in as an admin first.", "danger")
        return redirect(url_for('admin_login'))

    scholarships = Scholarship.query.all()
    return render_template('admin_dashboard.html', scholarships=scholarships)

@app.route('/add-scholarship', methods=['GET', 'POST'])
def add_scholarship():
    if not session.get('admin_logged_in'):
        flash("Access denied! Please log in as an admin.", "danger")
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        name = request.form.get('name')
        income_limit = request.form.get('income_limit')
        percentage_required = request.form.get('percentage_required')
        community = request.form.get('community')

        if not (name and income_limit and percentage_required and community):
            flash("All fields are required!", "danger")
            return redirect(url_for('admin_dashboard'))

        new_scholarship = Scholarship(
            name=name,
            income_limit=int(income_limit),
            percentage_required=int(percentage_required),
            community=community
        )

        db.session.add(new_scholarship)
        db.session.commit()
        flash("Scholarship added successfully!", "success")

        return redirect(url_for('admin_dashboard'))

    return render_template('add_scholarship.html')

@app.route('/delete-scholarship/<int:id>')
def delete_scholarship(id):
    if not session.get('admin_logged_in'):
        flash("Access denied!", "danger")
        return redirect(url_for('admin_login'))

    scholarship = Scholarship.query.get(id)
    if scholarship:
        db.session.delete(scholarship)
        db.session.commit()
        flash("Scholarship deleted successfully!", "success")
    else:
        flash("Scholarship not found!", "danger")

    return redirect(url_for('admin_dashboard'))

# ------------------------ DATABASE CREATION ------------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
