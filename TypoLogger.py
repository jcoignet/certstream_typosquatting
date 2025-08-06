import logging
import os
import sqlite3


class TypoLogger(logging.Logger):
    def __init__(self, name: str, alert_file: str = f'{os.path.dirname(os.path.abspath(__file__))}/suspicious_domains.log',
        log_file: str = f'{os.path.dirname(__file__)}/typosquatting.log', print_logs: bool = False, log_level: str = 'INFO',
        db_name: str = 'typosquatting.db', table_name: str = 'alerts'):
        super().__init__(name)
        self.setLevel(log_level)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        # Create the main handler
        fh_logs = logging.FileHandler(log_file, encoding='utf-8')
        fh_logs.setLevel(log_level)
        fh_logs.setFormatter(formatter)
        self.addHandler(fh_logs)

        # If print_logs is True, create an handler to output logs to the terminal
        if print_logs:
            ch = logging.StreamHandler()
            ch.setLevel(log_level)
            ch.setFormatter(formatter)
            self.addHandler(ch)

        # Create the alerts handler
        self.alert_logger = logging.Logger('suspicious_domains')
        alerts_logs = logging.FileHandler(alert_file, encoding='utf-8')
        alerts_logs.setLevel('INFO')
        alerts_logs.setFormatter(formatter)
        self.alert_logger.addHandler(alerts_logs)

        self.db_name = db_name
        self.table_name = table_name

    def alert(self, domain: str, ip: str, levenshtein_ratio: float, issuer: str, untrusted_issuer: bool,
              abuseipdb_score: int, typo_score: int, alert_level: str) -> None:
        '''Writes the alert informations to the main loggers, the alert logger and the database.'''
        try:
            birds = '\U0001f99c'
            if alert_level == 'MEDIUM':
                birds = '\U0001f99c' * 2
            elif alert_level == 'HIGH':
                birds = '\U0001f99c' * 3
            alert_str = f'ALERT "{domain}"/{ip} [{alert_level} {birds}/{typo_score}]: ratio {levenshtein_ratio}, trusted issuer "{issuer}" ? {untrusted_issuer}, abuse score: {abuseipdb_score}'
            self.info(alert_str)
            self.alert_logger.info(alert_str)
        except Exception:
            # Just in case the terminal doesn't like birds.
            alert_str = f'ALERT "{domain}"/{ip} [{alert_level}/{typo_score}]: ratio {levenshtein_ratio} trusted issuer "{issuer}" ? {untrusted_issuer}, abuse score: {abuseipdb_score}'
            self.info(alert_str)
            self.alert_logger.info(alert_str)
        try:
            # Add the alert to the db
            conn = sqlite3.connect(self.db_name)
            query = f'INSERT INTO {self.table_name}(domain,ip,levenshtein_ratio,issuer,untrusted_issuer,abuseipdb_score,typo_score,alert_level) VALUES(?,?,?,?,?,?,?,?)'
            cur = conn.cursor()
            cur.execute(
                query, (domain, ip, levenshtein_ratio, issuer, untrusted_issuer, abuseipdb_score, typo_score, alert_level)
            )
            conn.commit()
        except Exception as e:
            if str(e) == 'no such table: alerts':
                self.warning(f'Failed to insert into {self.db_name} table {self.table_name}: {e}. Try running "db_function.py create_table" first.')
            else:
                self.warning(f'Failed to insert into {self.db_name} table {self.table_name}: {e}')
