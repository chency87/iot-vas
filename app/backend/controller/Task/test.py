from app.backend.controller.Task.task import Schedule
from app.backend.controller.Task.task import Task
from app.backend.extensions import scheduler
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
        schedule={"triggers": "date"}
    )
    # # info = request.get_json(force=True)
    # sc = Schedule(info)
    # sc.add_task()
    print(scheduler.get_jobs())
    scheduler.remove_job(id='interval-5d83ba0a1a2649cba6484068e46866b5')
    while(True):
        pass

add_job()