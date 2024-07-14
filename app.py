from flask import Flask, jsonify, request, make_response
from flask_restful import Api, Resource, reqparse, fields, marshal_with
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import os
from datetime import timedelta

# Initialize Flask app and extensions
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///yachts.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
cors = CORS(app)
api = Api(app)

# Models
class Yacht(db.Model):
    __tablename__ = 'yachts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    capacity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    amenities = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<Yacht {self.name}>'

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

class Booking(db.Model):
    __tablename__ = 'bookings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    yacht_id = db.Column(db.Integer, db.ForeignKey('yachts.id'), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    num_guests = db.Column(db.Integer, nullable=False)
    special_requests = db.Column(db.Text, nullable=True)

    user = db.relationship('User', backref=db.backref('bookings', lazy=True))
    yacht = db.relationship('Yacht', backref=db.backref('bookings', lazy=True))

    def __repr__(self):
        return f'<Booking {self.id} by User {self.user_id} for Yacht {self.yacht_id}>'

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<Admin {self.username}>'

# Resources
yacht_fields = {
    'id': fields.Integer,
    'name': fields.String,
    'description': fields.String,
    'capacity': fields.Integer,
    'price': fields.String(attribute=lambda x: str(x.price)),
    'amenities': fields.String,
    'image_url': fields.String,
}

parser = reqparse.RequestParser()
parser.add_argument('name', type=str, required=True, help='Name is required')
parser.add_argument('description', type=str, required=False, help='Description of the yacht')
parser.add_argument('capacity', type=int, required=True, help='Capacity is required')
parser.add_argument('price', type=str, required=True, help='Price is required')
parser.add_argument('amenities', type=str, required=False, help='Amenities of the yacht')
parser.add_argument('image_url', type=str, required=True, help='Image URL is required')

class YachtListResource(Resource):
    @marshal_with(yacht_fields)
    def get(self):
        yachts = Yacht.query.all()
        return yachts

    @marshal_with(yacht_fields)
    @jwt_required()
    def post(self):
        args = parser.parse_args()
        yacht = Yacht(
            name=args['name'],
            description=args['description'],
            capacity=args['capacity'],
            price=args['price'],
            amenities=args['amenities'],
            image_url=args['image_url']
        )
        db.session.add(yacht)
        db.session.commit()
        return yacht, 201

class YachtResource(Resource):
    @marshal_with(yacht_fields)
    def get(self, id):
        yacht = Yacht.query.get_or_404(id)
        return yacht

    @jwt_required()
    def put(self, id):
        args = parser.parse_args()
        yacht = Yacht.query.get_or_404(id)
        yacht.name = args['name']
        yacht.description = args['description']
        yacht.capacity = args['capacity']
        yacht.price = args['price']
        yacht.amenities = args['amenities']
        yacht.image_url = args['image_url']
        db.session.commit()
        return {'message': 'Yacht updated successfully'}, 200

    @jwt_required()
    def delete(self, id):
        yacht = Yacht.query.get_or_404(id)
        db.session.delete(yacht)
        db.session.commit()
        return {'message': 'Yacht deleted successfully'}, 204

class UserRegister(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('email', type=str, required=True, help='Email is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()

        hashed_password = bcrypt.generate_password_hash(args['password']).decode('utf-8')

        new_user = User(
            username=args['username'],
            email=args['email'],
            password=hashed_password,
        )

        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User registered successfully'}, 201

class AdminLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True, help='Username is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()

        admin = Admin.query.filter_by(username=args['username']).first()
        if admin and bcrypt.check_password_hash(admin.password, args['password']):
            access_token = create_access_token(identity=admin.id)
            return {'access_token': access_token}, 200
        return {'message': 'Invalid credentials'}, 401

class UserLogin(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username_or_email', type=str, required=True, help='Username or email is required')
        parser.add_argument('password', type=str, required=True, help='Password is required')
        args = parser.parse_args()

        username_or_email = args['username_or_email']
        password = args['password']

        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=30))
            return {'access_token': access_token}, 200
        else:
            return {'message': 'Invalid credentials'}, 401

# API Routes
api.add_resource(YachtListResource, '/api/yachts')
api.add_resource(YachtResource, '/api/yachts/<int:id>')
api.add_resource(UserRegister, '/api/register')
api.add_resource(AdminLogin, '/api/admin-login')
api.add_resource(UserLogin, '/api/login')

if __name__ == '__main__':
    app.run(debug=True)
