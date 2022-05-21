from app.backend.database.database import db
from .table import Schedule_History
import ast


# 增
def add_schedule_history(id, create_time, end_time, params, scan_report):
    try:
        print(params['target'])
        print(type(params['target']))
        data = dict(
            task_id=str(id),
            create_time=str(create_time),
            end_time=str(end_time),
            params=str(params),  # info信息存在这里
            scan_report=str(scan_report),
            name=str(params['name']),
            target=str(params['target'])
        )
        df = Schedule_History(**data)
        db.session.add(df)
        db.session.commit()
    except Exception as e:
        print(e)


def delete_schedule_history(task_id):
    delete_history = Schedule_History.query.filter_by(task_id=task_id).first()
    db.session.delete(delete_history)
    db.session.commit()


def get_all_report(start, length, search):
    return_data = []
    return_data2 = {}
    start = int(start)
    length = int(length)
    search = ast.literal_eval(search)
    data = Schedule_History.query.all()
    for i in range(len(data)):
        return_data.append({})
        return_data[i]["name"] = ast.literal_eval(data[i + start].params)["name"]
        return_data[i]["config"] = ast.literal_eval(data[i + start].params)["config"]
        return_data[i]["id"] = data[i + start].task_id
        return_data[i]["createdAt"] = data[i + start].create_time
        return_data[i]["status"] = "Finished"
        return_data[i]["target"] = ast.literal_eval(data[i + start].params)["target"]
        return_data[i]["finished"] = data[i + start].end_time
        if i == length:
            break

    task_id = search.get('taskId')
    name = search.get('taskName')
    target = search.get('target')

    if task_id:
        print("select by id")
        return_data_byid = []
        for i in range(len(data)):
            if return_data[i]["id"] == task_id:
                return_data_byid.append(return_data[i])
        return_data2["data"] = return_data_byid
        return return_data2

    if name:
        return_data_byName = []
        print("select by name")
        for i in range(len(data)):
            if return_data[i]["name"] == name:
                return_data_byName.append(return_data[i])
        return_data2["data"] = return_data_byName
        return return_data2

    if target:
        print("select by target")
        return_data_byTarget = []
        for i in range(len(data)):
            if return_data[i]["target"] == target:
                return_data_byTarget.append(return_data[i])
        return_data2["data"] = return_data_byTarget
        return return_data2

    return_data2['data'] = return_data
    return return_data2


# 查
def get_report_by_id(task_id):
    data = Schedule_History.query.filter_by(task_id=task_id).first()
    params = ast.literal_eval(data.params)
    print(params)
    print(type(params))
    reportData = dict(
        task_id=data.task_id,
        create_time=data.create_time,
        end_time=data.end_time,
        params=dict(
            name=params["name"],
            config=params["config"],
            createdAt=data.create_time,
            status="Finished",
            target=params["target"],
            finished=data.end_time
        ),
        scan_report=ast.literal_eval(data.scan_report)
    )
    return reportData
