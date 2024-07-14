# models.py
from extensions import db

class Yacht(db.Model):
    __tablename__ = 'yachts'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    capacity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    amenities = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(255), nullable=False)  # New field for image URL

    def __repr__(self):
        return f'<Yacht {self.name}>'

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    vote_credits = db.Column(db.Integer, nullable=True)

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