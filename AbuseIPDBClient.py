import logging

from BaseClient import BaseClient


class AbuseIPDBClient(BaseClient):
    def __init__(self, base_url: str, api_key: str, headers: dict = {}, verify_ssl: bool = False, logger_name: str = None,
        logger: logging.Logger = None):
        # Add AbuseIPDB api key to the http headers
        headers['Key'] = api_key
        if 'Accept' not in headers:
            headers['Accept'] = 'application/json'
        # Remove slash at the end of the URL if present
        if base_url.endswith('/'):
            self.base_url = base_url[:-1]
        else:
            self.base_url = base_url
        self.api_key = api_key
        self.headers = headers
        super().__init__(base_url, headers, verify_ssl)
        # If a logger is provided, use it. Else create one.
        if logger:
            self.logger = logger
        else:
            self.logger = logging.Logger()

    def check_reputation(self, ip: str):
        '''Check the reputation of <ip> using AbuseIPDB api /check endpoint.
        Returns the AbuseIPDB score or -1 on error.'''
        if not ip or not len(ip):
            return -1
        endpoint = '/check'
        querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
        r = self.http_request(endpoint, 'GET', querystring)  # TODO HEADERS
        res = r.json().get('data')
        if not res:
            self.logger.error(f'AbuseIPDB request failure: {r.status_code}/{r.text}')
            return -1
        self.logger.debug(f'Domain: {res["domain"]}, AbuseIPDB score: {res["abuseConfidenceScore"]}')
        return res['abuseConfidenceScore']
