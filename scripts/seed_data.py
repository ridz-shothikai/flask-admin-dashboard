from app import create_app
from app.models import User, Application, FileCategory
from app.db import init_firestore
from datetime import datetime, timedelta


def seed_database():
    """Seed the database with sample data"""
    app = create_app()
    with app.app_context():
        # Initialize Firestore
        init_firestore(app)
        
        # Note: Firestore doesn't require clearing data like SQL databases
        # If you want to clear, you'd need to delete collections manually
        print("Seeding Firestore database...")

        # Create Applications
        print("Creating applications...")
        applications_data = [
            {
                'name': 'Dashboard',
                'description': 'Main admin dashboard',
                'url': 'https://dashboard.example.com',
                'status': 'active'
            },
            {
                'name': 'Region 14',
                'description': 'Region 14 management system',
                'url': 'https://region14.example.com',
                'status': 'active'
            },
            {
                'name': 'Region 2',
                'description': 'Region 2 management system',
                'url': 'https://region2.example.com',
                'status': 'active'
            },
            {
                'name': 'Analytics',
                'description': 'Analytics and reporting platform',
                'url': 'https://analytics.example.com',
                'status': 'maintenance'
            },
            {
                'name': 'Legacy System',
                'description': 'Old system being phased out',
                'url': 'https://legacy.example.com',
                'status': 'inactive'
            }
        ]
        
        applications = {}
        for app_data in applications_data:
            # Check if application already exists
            existing = Application.get_by_name(app_data['name'])
            if existing:
                applications[app_data['name']] = existing
                print(f"  Application already exists: {app_data['name']} (ID: {existing.id})")
            else:
                app = Application(**app_data)
                app.save()
                applications[app_data['name']] = app
                print(f"  Created application: {app_data['name']} (ID: {app.id})")
        
        print(f"Created/verified {len(applications)} applications")

        # Create File Categories
        print("Creating file categories...")
        VALID_CATEGORIES = [
            "1099",
            "CHECKS",
            "CHILD_WELFARE_REPORTS",
            "LEAVE_DOCUMENTS",
            "MONTH_END_REPORTS",
            "PAYROLL_REPORTS_N_DOCUMENTS",
            "PENDING_FILES",
            "PERSONNEL_FILES",
            "TRAVEL_REPORTS",
            "OTHER"
        ]
        
        file_categories = {}
        for category_code in VALID_CATEGORIES:
            # Check if category already exists
            existing = FileCategory.get_by_code(category_code)
            if existing:
                file_categories[category_code] = existing
                print(f"  File category already exists: {category_code} (ID: {existing.id})")
            else:
                # Create category with a formatted name
                category_name = category_code.replace('_', ' ').title()
                file_category = FileCategory(
                    code=category_code,
                    name=category_name,
                    description=f"File category for {category_name}",
                    status='active'
                )
                file_category.save()
                file_categories[category_code] = file_category
                print(f"  Created file category: {category_code} (ID: {file_category.id})")
        
        print(f"Created/verified {len(file_categories)} file categories")

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
                'role': 'superuser',
                'status': 'active',
                'first_name': 'John',
                'last_name': 'Administrator',
                'apps': ['Dashboard', 'Region 14', 'Region 2', 'Analytics']
            },
            {
                'email': 'user1@example.com',
                'password': 'User123!',
                'role': 'manager',
                'status': 'active',
                'first_name': 'Alice',
                'last_name': 'Johnson',
                'apps': ['Region 14']
            },
            {
                'email': 'user2@example.com',
                'password': 'User123!',
                'role': 'supervisor',
                'status': 'active',
                'first_name': 'Bob',
                'last_name': 'Smith',
                'apps': ['Region 2', 'Analytics']
            },
            {
                'email': 'inactive@example.com',
                'password': 'User123!',
                'role': 'staff',
                'status': 'inactive',
                'first_name': 'Charlie',
                'last_name': 'Inactive',
                'apps': []
            },
            {
                'email': 'newuser@example.com',
                'password': 'User123!',
                'role': 'staff',
                'status': 'active',
                'first_name': 'Diana',
                'last_name': 'New',
                'apps': ['Dashboard']
            }
        ]

        created_users = 0
        for user_data in users_data:
            # Check if user already exists
            existing = User.get_by_email(user_data['email'])
            if existing:
                print(f"  User already exists: {user_data['email']} (ID: {existing.id})")
                continue  # Skip creating duplicate user
            
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
            assigned_app_ids = []
            for app_name in user_data['apps']:
                if app_name in applications:
                    assigned_app_ids.append(applications[app_name].id)
            user.assigned_application_ids = assigned_app_ids

            user.save()
            created_users += 1
            print(f"  Created user: {user_data['email']} (ID: {user.id})")

        print(f"Created/verified {len(users_data)} users ({created_users} new, {len(users_data) - created_users} existing)")

        print("\nDatabase seeded successfully!")
        print("\nSample credentials:")
        print("Superadmin: superadmin@example.com / SuperAdmin123!")
        print("Admin: admin@example.com / Admin123!")
        print("User: user1@example.com / User123!")


if __name__ == '__main__':
    seed_database()
