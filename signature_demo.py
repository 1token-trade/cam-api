import base64
import hashlib
import hmac
import json
import time

import requests

from configuration import api_key, api_secret, url_prefix


def gen_timestamp():
    return int(time.time())


def gen_headers(time_stamp, key, sig):
    headers = {
        'Api-Timestamp': str(time_stamp),
        'Api-Key': key,
        'Api-Signature': sig,
        'Content-Type': 'application/json'
    }
    return headers


def gen_sign(secret, verb, path, timestamp, data=None):
    if data is None:
        data_str = ''
    else:
        assert isinstance(data, dict)
        # server并不要求data_str按key排序，只需此处用来签名的data_str和所发送请求中的data相同即可，是否排序请按实际情况选择
        data_str = json.dumps(data)
    message = verb + path + str(timestamp) + data_str
    print("message:", message)
    signature = hmac.new(base64.b64decode(secret), bytes(message, 'utf8'), digestmod=hashlib.sha256)
    signature = base64.b64encode(signature.digest()).decode()
    print('signature:', signature)
    return signature


def api_request(method, path, data=None):
    timestamp = gen_timestamp()
    sig = gen_sign(api_secret, method, path, timestamp, data)
    headers = gen_headers(timestamp, api_key, sig)
    if data is not None:
        post_data = json.dumps(data).encode('utf-8')
    else:
        post_data = None
    resp = requests.request(method, url_prefix + path, headers=headers, data=post_data)
    try:
        resp_data = resp.json()
        print("get response", resp_data)
    except BaseException as e:
        print("get error response", resp.text)
        return None
    return resp_data


def get_demo():
    verb = 'GET'
    path = '/tradeacc/public-key'
    api_request(verb, path)


def post_demo():
    verb = 'POST'
    path = '/otc-assets/broker/loan/collateral-valuation-haircut-setting'
    post_data = {
        "underlying": "btc",
        "week_section": [0, 0, 0, 0, 0, 0, 1],
        "start_time": "00:00",
        "end_time": "23:59",
        "timezone": "+08:00",
        "discount_rate": "0.5",
    }
    api_request(verb, path, post_data)


if __name__ == '__main__':
    print("start test get request")
    get_demo()
    print("start test post request")
    post_demo()
