from flask import Flask, jsonify, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash  # Импортируем необходимые функции

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
jwt = JWTManager(app)

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)  # Шифрование пароля

    def check_password(self, password):
        return check_password_hash(self.password, password)  # Проверка пароля

# Модель транзакции
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Загрузка пользователя для сессии Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Маршрут для главной страницы
@app.route('/')
def home():
    return "Hello, Fiódor!"

# Маршрут для аутентификации пользователя и создания JWT токена
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and user.check_password(data['password']):
        access_token = create_access_token(identity={'username': user.username, 'email': user.email, 'user_id': user.id})
        login_user(user)
        return jsonify(access_token=access_token)
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# Маршрут для выхода из системы
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logged out"}), 200

# Маршрут для получения профиля текущего пользователя
@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    identity = get_jwt_identity()
    user = User.query.filter_by(username=identity['username']).first()
    return jsonify({
        'username': user.username,
        'email': user.email
    })

# Маршрут для получения списка пользователей (требуется JWT аутентификация)
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = User.query.all()
    users_data = [{"id": user.id, "username": user.username, "email": user.email} for user in users]
    return jsonify(users_data)

# Маршрут для создания нового пользователя (с шифрованием пароля)
@app.route('/users', methods=['POST'])
def create_user():
    data = request.get_json()
    if not data or not 'username' in data or not 'email' in data or not 'password' in data:
        return jsonify({"error": "Invalid data"}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "Email already exists"}), 400

    new_user = User(username=data['username'], email=data['email'])
    new_user.set_password(data['password'])  # Шифруем пароль перед сохранением
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created"}), 201

# Маршрут для обновления данных пользователя
@app.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    identity = get_jwt_identity()
    if identity['user_id'] != user_id:
        return jsonify({"error": "Unauthorized access"}), 403

    user = User.query.get_or_404(user_id)
    data = request.get_json()
    if 'username' in data:
        user.username = data['username']
    if 'email' in data:
        user.email = data['email']
    if 'password' in data:
        user.set_password(data['password'])  # Шифруем новый пароль перед сохранением

    db.session.commit()
    return jsonify({"message": "User updated"}), 200

# Маршрут для удаления пользователя
@app.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    identity = get_jwt_identity()
    if identity['user_id'] != user_id:
        return jsonify({"error": "Unauthorized access"}), 403

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted"}), 200

# Маршрут для получения списка транзакций
@app.route('/transactions', methods=['GET'])
def get_transactions():
    transactions = Transaction.query.all()
    transactions_data = [{"id": transaction.id, "amount": transaction.amount, "user_id": transaction.user_id} for transaction in transactions]
    return jsonify(transactions_data)

# Маршрут для создания новой транзакции
@app.route('/transactions', methods=['POST'])
def create_transaction():
    data = request.get_json()
    new_transaction = Transaction(amount=data['amount'], user_id=data['user_id'])
    db.session.add(new_transaction)
    db.session.commit()
    return jsonify({"message": "Transaction created"}), 201

if __name__ == "__main__":
    app.run(debug=True)
