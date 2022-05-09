from werkzeug.wrappers import request
from app.backend.models.user import User
from app.backend import error
from app.backend.database.database import db
from app.conf.auth import auth, refresh_jwt

from app.backend.schema.schemas import BaseUserSchema, UserSchema
from app.backend.permission.role_required import Role
from werkzeug.security import check_password_hash, generate_password_hash
from app.backend.error import status
from app.backend.error.apiexception import AuthFailed
from datetime import datetime



def add_update_user(id, username, password, email, user_role):

    if id:
        user = User.query.filter_by(id=id).first()
        user.username = username if username else user.username
        user.password = generate_password_hash(password) if password else user.password
        user.email = email if email else user.email
        user.user_role = user_role if user_role else user.user_role
        user.modified = datetime.now()
        # print('update user %s' % user)
            # Commit session.
        db.session.commit()
    else:
        if username is None or password is None or email is None or user_role is None:
            return error.INVALID_INPUT_422
        user = User.query.filter_by(username=username).first()
        if user is not None:
            return error.ALREADY_EXIST
        user = User(username=username, password=generate_password_hash(password), email=email, user_role = user_role, created = datetime.now(), modified =  datetime.now(), lastlogin = None)
        db.session.add(user)
        # print('add user %s' % user)
            # Commit session.
        db.session.commit()


    # Return success if registration is completed.
    return error.SUCCESS_200

def update_user(id, username, email):
    user = User.query.filter_by(id=id).first()
    user.username = username
    user.email = email
    db.session.commit()
    user = User.query.filter_by(id=id).first()
    if user:
        return user
    return None



def query_user(username):
    user = User.query.filter_by(username=username).first()
    data = UserSchema().dump(user)
    if user:
        return data
    return None

def query_all_user():
    user = User.query.all()
    user_schema = BaseUserSchema(many=True)
    return user_schema.dump(user)
    
def delete_users(ids):
    for id in ids:
        User.query.filter_by(id=id).delete()
    db.session.commit()

    

def login(username, password):
    # Check if user information is none.
    if username is None or password is None:
        return error.INVALID_INPUT_422
    # Get user if it is existed. 
    user = User.query.filter_by(username=username).first()
    if user is None:
        return error.INVALID_INPUT_422
    if not check_password_hash(user.password, password):
        return error.UNAUTHORIZED
    access_token = user.generate_auth_token(user.user_role)
    refresh_token = refresh_jwt.dumps({"username": username})
    # Return access token and refresh token.
    return ({
        "access_token": access_token.decode(),
        "refresh_token": refresh_token.decode(),
        'user_info': user
    },200)

def reset_password(username, old_pass, new_pass):
    user = User.query.filter_by(username=username).first()
    if user.password != generate_password_hash(old_pass):
            return status.OLD_PASS_DOES_NOT_MATCH
    user.password = generate_password_hash(new_pass)
    db.session.commit()
    return status.PASS_CHANGED




def logout(refresh_token):
    
    pass
    # ref = Blacklist.query.filter_by(refresh_token=refresh_token).first()
    # # Check refresh token is existed.
    # if ref is not None:
    #     return {"status": "already invalidated", "refresh_token": refresh_token}

    # # Create a blacklist refresh token.
    # blacklist_refresh_token = Blacklist(refresh_token=refresh_token)

    # # Add refresh token to session.
    # db.session.add(blacklist_refresh_token)

    # # Commit session.
    # db.session.commit()

    # # Return status of refresh token.
    # return {"status": "invalidated", "refresh_token": refresh_token}