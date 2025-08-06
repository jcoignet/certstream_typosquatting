import certstream
import socket

from AbuseIPDBClient import AbuseIPDBClient
from Levenshtein import ratio
from TypoLogger import TypoLogger


class CertstreamHandler(object):
    abuseipdb_client = None
    certstream_url = ''
    conf = {}
    logger = None

    def __init__(self, logger: TypoLogger, conf: dict):
        self.logger = logger
        self.certstream_url = conf.get('CERTSTREAM_URL')
        self.conf = conf
        self.abuseipdb_client = AbuseIPDBClient(
            conf.get('ABUSEIPDB_BASE_URL', 'https://api.abuseipdb.com/api/v2'),
            conf.get('ABUSEIPDB_API_KEY'),
            headers=conf.get('HTTP_HEADERS', {}),
            verify_ssl=conf.get('VERIFY_SSL', True),
            logger_name=self.logger.name,
            logger=self.logger,
        )
        self.get_certstream_events()

    def get_certstream_events(self):
        '''Starts the listen_for_events certstream function which will call certstream_analysis.'''
        self.logger.debug(f'Starting connection to Certstream server {self.certstream_url}.')
        certstream.listen_for_events(
            self.certstream_analysis,
            on_open=self.certstream_on_open,
            on_error=self.certstream_on_error,
            url=self.certstream_url,
        )

    def certstream_on_open(self):
        '''Called when the Certstream listener successfully connects.'''
        self.logger.debug('Connection successfull.')

    def certstream_on_error(self, exception):
        '''Called when an error occurs with Certstream.'''
        self.logger.error(f'Connection to Certstream closed: {exception}.')

    def check_issuer(self, message: dict) -> bool:
        '''Checks if the issuer is present in the UNTRUSTED_ISSUERS param of the configuration file.'''
        issuer = message.get('data', {}).get('leaf_cert', {}).get('issuer', {}).get('O')
        if issuer in self.conf.get('UNTRUSTED_ISSUERS', []):
            self.logger.debug(f'Untrusted issuer {issuer} found.')
            return issuer, True
        return issuer, False

    def calculate_typoscore(self, levenshtein_ratio: float, untrusted_issuer: bool, abuseipdb_score: int) -> int:
        '''Heuristic to calculate custom score based on distance, untrusted issuer and AbuseIPDB score.
        typo_score = abuseipdb_score + (radio * 100) + 20 (if the issuer is unstrusted)'''
        typo_score = 0
        if untrusted_issuer:
            typo_score += 20
        # If abuseipdb_score is -1 it means that we didn't get the score before (failed to get ip from domain, throttle...)
        if abuseipdb_score >= 0:
            typo_score += abuseipdb_score
        typo_score += int(levenshtein_ratio * 100)
        alert_level = 'LOW'
        if typo_score >= 100:
            alert_level = 'MEDIUM'
        if typo_score >= 150:
            alert_level = 'HIGH'
        return typo_score, alert_level

    def new_alert(self, message: dict, domain: str, levenshtein_ratio: float):
        # Check if issuer is in unstrusted list
        issuer, untrusted_issuer = self.check_issuer(message)

        # Get IP of the domain
        try:
            ip = socket.gethostbyname(domain)
        except Exception as e:
            self.logger.warning(f'Failed to get IP of domain {domain}: {e}')
            ip = None

        # Check AbuseIPDB score
        if ip:
            try:
                abuseipdb_score = self.abuseipdb_client.check_reputation(ip)
            except Exception as e:
                abuseipdb_score = -1
                self.logger.error(f'Failed to get AbuseIPDB score: {e}.')
        else:
            abuseipdb_score = -1

        typo_score, alert_level = self.calculate_typoscore(levenshtein_ratio, untrusted_issuer, abuseipdb_score)
        self.logger.alert(domain, ip, levenshtein_ratio, issuer, untrusted_issuer, abuseipdb_score, typo_score, alert_level)

    def certstream_analysis(self, message, context):
        '''Main analysis function, called when a new Certstream event is received.
        It will generate an alert if the event's domain is close to our domain using Levenshtein ratio.'''
        self.logger.debug(message)
        # Get the certificate domains
        domains = message.get('data', {}).get('leaf_cert', {}).get('all_domains', [])
        for domain in domains:
            levenshtein_ratio = ratio(self.conf.get('MY_DOMAIN'), domain)
            # If the ratio is superior to the selected minimum, we raise an alert
            if levenshtein_ratio >= self.conf.get('MIN_RATIO', 0.7):
                self.logger.debug(f'RATIO {levenshtein_ratio} for {domain}')
                self.new_alert(message, domain, levenshtein_ratio)
