from app.backend.database.database import db
from .table import Schedule_History


# 增
def add_schedule_history(id, create_time, end_time, params, scan_report):
    data = dict(
        task_id=str(id),
        create_time=str(create_time),
        end_time=str(end_time),
        params=str(params),  # info信息存在这里
        scan_report=str(scan_report)
    )
    df = Schedule_History(**data)
    db.session.add(df)
    db.session.commit()


def delete_schedule_history(task_id):
    delete_history = Schedule_History.query.filter_by(task_id=task_id).first()
    db.session.delete(delete_history)
    db.session.commit()


# 查
def get_report_by_id(id):
    if id is None:
        return None
    report = Schedule_History.query.filter_by(id=id).first()
    return report
