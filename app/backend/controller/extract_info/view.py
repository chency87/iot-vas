from flask import jsonify, render_template, request

from . import extract_info

@extract_info.route('/extract_info/details', methods=['GET'])
def show_details():
    try:
        pass
    except Exception as e:
        print(e)
   # add.CryptoKey_add_update('1','1','1','1',1)
    print("helloworld")
    return "extract_info/details"

@extract_info.route('/extract_info/extract_from_banner/', methods=['POST'])
def extract_from_banner():

    banner_text = request.form.get('banner')
    banner_list = banner_text.split()
    print(banner_list)

    print("extract_info/extract_from_banner")
    response = {'status': 200, 'data': banner_text}
    return jsonify(response)

