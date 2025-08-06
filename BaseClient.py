import requests


class BaseClient(object):
    def __init__(self, base_url: str, headers: dict = {}, verify_ssl: bool = False):
        self.base_url = base_url
        self.headers = headers
        self.verify_ssl = verify_ssl

    def http_request(self, endpoint: str, method: str, json_body: dict):
        r = requests.request(method, self.base_url + endpoint, params=json_body, headers=self.headers, verify=self.verify_ssl)
        return r
