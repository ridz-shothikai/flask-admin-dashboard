from app import create_app, db
from app.models import User, Application
from datetime import datetime, timedelta


def seed_database():
    """Seed the database with sample data"""
    app = create_app()
    with app.app_context():
        # Clear existing data
        print("Clearing existing data...")
        db.drop_all()
        db.create_all()

        # Create Applications
        print("Creating applications...")
        applications = [
            Application(
                name='Dashboard',
                description='Main admin dashboard',
                url='https://dashboard.example.com',
                status='active'
            ),
            Application(
                name='Region 14',
                description='Region 14 management system',
                url='https://region14.example.com',
                status='active'
            ),
            Application(
                name='Region 2',
                description='Region 2 management system',
                url='https://region2.example.com',
                status='active'
            ),
            Application(
                name='Analytics',
                description='Analytics and reporting platform',
                url='https://analytics.example.com',
                status='maintenance'
            ),
            Application(
                name='Legacy System',
                description='Old system being phased out',
                url='https://legacy.example.com',
                status='inactive'
            )
        ]
        for app_item in applications:
            db.session.add(app_item)
        db.session.commit()
        print(f"Created {len(applications)} applications")

        # Create Users
        print("Creating users...")
        users_data = [
            {
                'email': 'superadmin@example.com',
                'password': 'SuperAdmin123!',
                'role': 'superadmin',
                'status': 'active',
                'first_name': 'Super',
                'last_name': 'Admin',
                'apps': ['Dashboard', 'Region 14', 'Region 2', 'Analytics']
            },
            {
                'email': 'admin@example.com',
                'password': 'Admin123!',
                'role': 'admin',
                'status': 'active',
                'first_name': 'John',
                'last_name': 'Administrator',
                'apps': ['Dashboard', 'Region 14']
            },
            {
                'email': 'user1@example.com',
                'password': 'User123!',
                'role': 'user',
                'status': 'active',
                'first_name': 'Alice',
                'last_name': 'Johnson',
                'apps': ['Region 14']
            },
            {
                'email': 'user2@example.com',
                'password': 'User123!',
                'role': 'user',
                'status': 'active',
                'first_name': 'Bob',
                'last_name': 'Smith',
                'apps': ['Region 2', 'Analytics']
            },
            {
                'email': 'inactive@example.com',
                'password': 'User123!',
                'role': 'user',
                'status': 'inactive',
                'first_name': 'Charlie',
                'last_name': 'Inactive',
                'apps': []
            },
            {
                'email': 'newuser@example.com',
                'password': 'User123!',
                'role': 'user',
                'status': 'active',
                'first_name': 'Diana',
                'last_name': 'New',
                'apps': ['Dashboard']
            }
        ]

        for user_data in users_data:
            user = User(
                email=user_data['email'],
                role=user_data['role'],
                status=user_data['status'],
                first_name=user_data['first_name'],
                last_name=user_data['last_name']
            )
            user.set_password(user_data['password'])

            # Set last login for active users (random dates in last 30 days)
            if user_data['status'] == 'active':
                days_ago = hash(user_data['email']) % 30
                user.last_login = datetime.utcnow() - timedelta(days=days_ago)

            # Assign applications
            for app_name in user_data['apps']:
                app = Application.query.filter_by(name=app_name).first()
                if app:
                    user.assigned_applications.append(app)

            db.session.add(user)
        db.session.commit()
        print(f"Created {len(users_data)} users")

        print("\nDatabase seeded successfully!")
        print("\nSample credentials:")
        print("Superadmin: superadmin@example.com / SuperAdmin123!")
        print("Admin: admin@example.com / Admin123!")
        print("User: user1@example.com / User123!")


if __name__ == '__main__':
    seed_database()

