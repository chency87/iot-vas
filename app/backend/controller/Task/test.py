from app.backend.controller.Task.task import Schedule
from app.backend.controller.Task.task import Task
from app.backend.extensions import scheduler
from app.backend.models.Task_data.table import Schedule_History
def add_job():
    info = dict(
        name="123",
        target="198.53.49.46",
        task_id="",
        port="1-1000",
        rate=10000,
        scan_type=["UDP_Scan"],
        config=["service", "banner"],
        scan_desc="",
        script=["snmp*"],
        schedule={"triggers": "interval"}
    )
    # info = request.get_json(force=True)
    sc = Schedule(info)
    sc.add_new_task()
    # print(scheduler.get_jobs())
    # scheduler.remove_job(id='')
    while(True):
        pass

add_job()

# page = 1
# data1 = Schedule_History.query.filter_by(task_id='date-9b19347fbdfd44c29498d3cdfc81b799').first()
# data2 = Schedule_History.query.all()
#
# print(data2)