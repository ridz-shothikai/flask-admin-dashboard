import os
from app import create_app, db

app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'True') == 'True'

    with app.app_context():
        # Create tables if they don't exist
        db.create_all()

    app.run(host='0.0.0.0', port=port, debug=debug)

