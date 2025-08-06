#!/usr/bin/env python3

import json
import logging
import os
import sys

from TypoLogger import TypoLogger
from CertstreamHandler import CertstreamHandler

def get_configuration() -> dict:
    '''Get the configuration from the file in the first script argument if provided \
else from the conf.json file in this script directory.
    '''
    args = sys.argv[1:]
    try:
        if len(args) == 1:
            conf = json.load(open(args[0]))
        else:
            conf = json.load(open(os.path.dirname(__file__) + '/conf.json'))
    except FileNotFoundError:
        print(
            'ERROR: Unable to load configuration file. The conf file must be named conf.json \
    and located in the same directory as the script, or passed as the script first argument.'
        )
        exit(-1)
    except json.decoder.JSONDecodeError:
        print('ERROR: The provided conf file is not a valid json file.')
        exit(-1)
    return conf


def main():
    conf = get_configuration()
    # Get the path to the general log file from conf value of LOG_FILE
    # else create it as typosquatting.log in the same directory than this script
    log_file = conf.get(
        'LOG_FILE', os.path.dirname(os.path.abspath(__file__)) + '/typosquatting.log'
    )
    # Get the path to the suspicious domains log file from conf value of LOG_FILE
    # else create it as typosquatting.log in the same directory than this script
    alert_file = conf.get(
        'SUSPICIOUS_DOMAINS_FILE',
        os.path.dirname(os.path.abspath(__file__)) + '/suspicious_domains.log',
    )

    # Set the log level to the conf value of LOG_LEVEL, else log level INFO will be used
    logger = TypoLogger(
        os.path.basename(__file__),
        log_level=conf.get('LOG_LEVEL'),
        log_file=log_file,
        alert_file=alert_file,
        print_logs=conf.get('PRINT_LOGS'),
    )
    logging.debug(json.dumps(conf, indent=2, ensure_ascii=False))

    _certstream_handler = CertstreamHandler(logger, conf)


if __name__ == '__main__':
    main()
