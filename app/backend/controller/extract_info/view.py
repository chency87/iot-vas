from . import extract_info

from app.backend.models import add,delete

@extract_info.route('/extract_info/details', methods=['GET'])
def show_details():
    try:
        add.CryptoKey_add_update(None,'hasdase','jeasdas','ssdsda','ssdsd',100)
        add.CryptoKey_add_update(None,'213123121312','je','sda','sd',100)
        delete.CryptoKey_delete(None,None,'je',None,None,None)
    except Exception as e:
        print(e)
   # add.CryptoKey_add_update('1','1','1','1',1)
    print("helloworld")
    return "extract_info/details"

