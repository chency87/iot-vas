# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, PasswordField
from wtforms.validators import DataRequired

# 定义的表单都需要继承自FlaskForm
class LoginForm(FlaskForm):
    # 域初始化时，第一个参数是设置label属性的
    username = StringField('User Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('remember me', default=False)


class UserProfileForm(FlaskForm):
    username = StringField('用户名称', validators=[DataRequired()])
    email = StringField('邮箱', validators=[DataRequired()])
    role = StringField('用户角色', validators=[DataRequired()])
    created = StringField('账号创建时间', validators=[DataRequired()])
    lastlogin = StringField('上次登陆时间', validators=[DataRequired()])