

from datetime import datetime

from flask import g
from app.conf.auth import auth, jwt
from app.backend.database.database import db

from flask_login import UserMixin
from app.backend.permission.role_required import Role


class User(UserMixin, db.Model):
    __tablename__ = 'user_info'

    # User id.
    id = db.Column(db.Integer, primary_key=True)
    # User name.
    username = db.Column(db.String(length=80))
    # User password.
    password = db.Column(db.String(80))
    # User email address.
    email = db.Column(db.String(length=80))
    # Creation time for user.
    created = db.Column(db.DateTime, default=datetime.utcnow)
    # Modifie time for user.
    modified = db.Column(db.DateTime, default=datetime.utcnow)
    # Unless otherwise stated default role is user.
    user_role = db.Column(db.String, default=Role.user)
    # Last Login Time
    lastlogin = db.Column(db.DateTime, default=datetime.utcnow)




    # Generates auth token.
    def generate_auth_token(self, permission_level):
        return jwt.dumps({"username": self.username, "admin": permission_level})

    # Generates a new access token from refresh token.
    @staticmethod
    @auth.verify_token
    def verify_auth_token(token):

        # Create a global none user.
        g.user = None
        try:
            # Load token.
            data = jwt.loads(token)
        except:
            # If any error return false.
            return False
        # Check if email and admin permission variables are in jwt.
        if "username" and "admin" in data:
            # Set email from jwt.
            g.user = data["username"]

            # Set admin permission from jwt.
            g.admin = data["admin"]
            # Return true.
            return True
        # If does not verified, return false.
        return False


    def __repr__(self):
        return "<User(id='%s', name='%s', password='%s', email='%s', role= '%s',created='%s', modified='%s', lastlogin= '%s')>" % (
            self.id,
            self.username,
            self.password,
            self.email,
            self.user_role,
            self.created,
            self.modified,
            self.lastlogin
        )
