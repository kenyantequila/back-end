# seed.py
from random import randint, uniform
from faker import Faker
from app import create_app
from extensions import db
from models import Yacht, User
import uuid

def seed_data():
    app = create_app()

    with app.app_context():
        print("Starting seed...")

        db.drop_all()
        db.create_all()

        print("Database tables created.")

        fake = Faker()

        Yachts = [
            Yacht(
                name=fake.company(),
                description=fake.text(max_nb_chars=500),
                capacity=randint(1, 200),
                price=round(uniform(100, 9999.99), 2),
                amenities=fake.text(max_nb_chars=200)
            )
            for _ in range(100)
        ]
        
        try:
            db.session.add_all(Yachts)
            db.session.commit()
            print("Yachts seeding complete.")
        except Exception as e:
            print(f"Error seeding Yachts: {str(e)}")
            db.session.rollback()

        Users = []
        for _ in range(1000):
            while True:
                username = fake.user_name() + str(uuid.uuid4())[:8]
                if not User.query.filter_by(username=username).first():
                    user = User(
                        username=username,
                        email=fake.email(),
                        password=fake.password(length=10),
                        vote_credits=randint(0, 100)
                    )
                    Users.append(user)
                    break
        
        try:
            db.session.add_all(Users)
            db.session.commit()
            print("Users seeding complete.")
        except Exception as e:
            print(f"Error seeding Users: {str(e)}")
            db.session.rollback()

if __name__ == '__main__':
    seed_data()