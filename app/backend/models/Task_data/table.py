from app.backend.database.database import db


class Schedule_History(db.Model):
    __tablename__ = ' schedule_history'

    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.String(256))
    create_time = db.Column(db.String(240))
    params = db.Column(db.Text)
    end_time = db.Column(db.String(240))
    scan_report = db.Column(db.Text)
    name = db.Column(db.String(256))
    target = db.Column(db.String(256))
    def __repr__(self):
        return "{id:'%d', task_id:'%s', create_time:'%s',params:'%s', end_time:'%s',scan_report:'%s',name:'%s',target:'%s'}" % (
            self.id,
            self.task_id,
            self.create_time,
            self.params,
            self.end_time,
            self.scan_report,
            self.name,
            self.target
        )

    def to_json(self):
        json_post = {
            'id': self.id,
            'task_id': self.task_id,
            'create_time': self.create_time,
            'params': self.params,
            'end_time': self.end_time,
            'scan_report': self.scan_report
        }
        return json_post
