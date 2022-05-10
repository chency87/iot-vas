from . import Task


@Task.route('/creat_task', methods=['GET'])
def helloworld():
    return 'hello'
