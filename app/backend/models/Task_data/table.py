from app.backend.database.database import db


class Schedule_History (db.Model):
    __tablename__ = ' schedule_history'

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(256))
    create_time = db.Column(db.String(240))
    params = db.Column(db.Text)
    end_time = db.Column(db.String(240))
    scan_result = db.Column(db.String(240))