import logging

from app.backend.database.database import db
# from app.backend.models

import logging

from app.backend.database.database import db
from app.backend.models.user import User
from app.backend.permission.role_required import Role
from werkzeug.security import generate_password_hash
import base64

def create_super_admin():

    # Check if admin is existed in db.
    user = User.query.filter_by(username="sa").first()
    # If user is none.
    if user is None:
        # Create admin user if it does not existed.
        pw = None
        # base64.encode(generate_password_hash("sa123456"),pw)
        password=generate_password_hash('sa123456',method = 'plain'),
        # print(password)
        
        
        user = User(
            username="sa",
            password=password,
            email="sa_email@example.com",
            user_role= Role.sa,
        )

        # Add user to session.
        db.session.add(user)

        # Commit session.
        db.session.commit()

        # Print admin user status.
        logging.info("Super admin was set.")

    else:

        # Print admin user status.
        logging.info("Super admin already set.")


def create_admin_user():

    # Check if admin is existed in db.
    user = User.query.filter_by(username="admin").first()
    # If user is none.
    if user is None:
        # Create admin user if it does not existed.
        pw = None
        # base64.encode(generate_password_hash("admin"),pw)
        user = User(
            username="admin",
            password="111111",
            email="admin34_email@example.com",
            user_role=Role.admin,
        )

        # Add user to session.
        db.session.add(user)

        # Commit session.
        db.session.commit()

        # Print admin user status.
        logging.info("Admin was set.")

    else:
        # Print admin user status.
        logging.info("Admin already set.")


def create_test_user(
    username="test",
    password=generate_password_hash("admin", method='plain'),
    email="test_email@example.com",
    user_role=Role.user,
):

    # Check if admin is existed in db.
    user = User.query.filter_by(username="test").first()

    # If user is none.
    if user is None:

        # Create admin user if it does not existed.
        # user = User(username=username, password=password, email=email, user_role=user_role)
        user = User(
            username=username,
            password=password,
            email=email,
            user_role=user_role,
        )

        # Add user to session.
        db.session.add(user)

        # Commit session.
        db.session.commit()

        # Print admin user status.
        logging.info("Test user was set.")

        # Return user.
        return user

    else:

        # Print admin user status.
        logging.info("User already set.")
