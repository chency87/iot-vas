from app.backend.database.database import db
from .table import Schedule_History
import ast


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


def get_all_report(start, length, params):
    data = Schedule_History.query.all()

    return_data = []
    return_data2 = {}
    start = int(start)
    length =int(length)
    params = params
    for i in range(len(data)):
        return_data.append({})
        return_data[i]['name'] = ast.literal_eval(data[i + start].params)['name']
        return_data[i]['config'] = '不知道是啥'
        return_data[i]['id'] = data[i + start].task_id
        return_data[i]['createdAt'] = data[i + start].create_time
        return_data[i]['status'] = 'finished'
        return_data[i]['target'] = ast.literal_eval(data[i + start].params)['target']
        return_data[i]['finished'] = data[i + start].end_time
        if i == length:
            break
    return_data2["data"] = return_data
    return return_data2


# 查
def get_report_by_id(id):
    if id is None:
        return None
    report = Schedule_History.query.filter_by(id=id).first()
    return report
