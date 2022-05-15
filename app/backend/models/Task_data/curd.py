from app.backend.models.Task_data.table import Schedule_History
from app.backend.database.database import db


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


