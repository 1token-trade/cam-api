import base64

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from signature_demo import api_request


# get public key to encrypt api
def get_public_key():
    verb = 'GET'
    path = '/tradeacc/public-key'
    resp = api_request(verb, path)
    if resp is None:
        return resp
    return resp["data"]


# get proxy id in CAM which bound to api in exchange
def get_proxy_id(external_ip):
    verb = 'GET'
    path = '/config/proxy/list'
    resp = api_request(verb, path)
    if resp is None:
        return resp
    proxy_list = resp.get('data', [])
    is_direct = False
    if external_ip == "direct":
        is_direct = True
    for proxy in proxy_list:
        if is_direct and proxy['is_direct']:
            return proxy['id']
        if proxy['external_ip'] == external_ip:
            return proxy['id']
    return None


def encrypt(public_key, plain_text):
    if not public_key.startswith("-----BEGIN PUBLIC KEY-----\n"):
        public_key = "-----BEGIN PUBLIC KEY-----\n" + public_key
    if not public_key.endswith("\n-----END PUBLIC KEY-----"):
        public_key = public_key + "\n-----END PUBLIC KEY-----"
    pub_key = RSA.importKey(public_key)
    cipher = PKCS1_v1_5.new(pub_key)
    rsa_text = base64.b64encode(cipher.encrypt(bytes(plain_text.encode("utf8")))).decode("utf8")
    return rsa_text


def create_trade_account(exchange, alias, exchange_mom_sub, exchange_api_key=None, exchange_api_secret=None,
                         proxy_external_ip=None):
    post_body = {
        "exchange": exchange,
        "alias": alias,
        "exg_mom_sub": exchange_mom_sub,
        "exchange_package_all": True,
        "exchange_type_show": []
    }
    if exchange_api_key is not None:
        public_key = get_public_key()
        if public_key is None:
            print("get public key error")
            return
        encrypted_api_key = encrypt(public_key, exchange_api_key)
        encrypted_api_secret = encrypt(public_key, exchange_api_secret)
        proxy_id = get_proxy_id(proxy_external_ip)
        if proxy_id is None:
            print("get proxy id error")
            return
        post_body["api"] = {
            "api_key": encrypted_api_key,
            "api_secret": encrypted_api_secret
        }
        post_body["proxies"] = [{
            "proxy_id": proxy_id
        }]
    verb = 'POST'
    path = '/tradeacc/create-account'
    resp = api_request(verb, path, post_body)
    print("create tradeacc", resp)


def get_trade_account_list():
    verb = 'GET'
    path = '/tradeacc/list-all-accounts'
    resp = api_request(verb, path)
    if resp is None:
        return None
    if 'account' not in resp.keys():
        print("error resp", resp)
        return None
    return resp.get('account', [])


def delete_trade_account(name):
    verb = 'POST'
    path = '/tradeacc/delete-account'
    post_body = {
        'name': name
    }
    resp = api_request(verb, path, post_body)
    print("delete account", resp)


def delete_trade_account_with_alias(alias):
    account_list = get_trade_account_list()
    if account_list is None:
        print("get trade account list error")
        return
    for account in account_list:
        if account['alias'] == alias:
            delete_trade_account(account['name'])
            break


if __name__ == '__main__':
    print("add trade account without api")
    create_trade_account("bnprop", "test-no-api", "mom")
    print("delete account")
    delete_trade_account_with_alias("test-no-api")
    print("-------------------------------------------------------------------------------------------------------")
    print("add trade account with api")
    create_trade_account("bnprop", "test-with-api", "mom",
                         "kJf4USfmgLHgaUsD7S0KCzX6K0pHnic8TppzlUY9e57BlKY8MhUxq2l40mUS4p4n",
                         "6DyeOSNcfq2iGcvkqhu3uFkb4ZynnswSnuPTa04A7XYDf6bwMXeVsCpK3J736z7N", "direct")
    print("delete account")
    delete_trade_account_with_alias("test-with-api")
