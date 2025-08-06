# typosquatting
Typosquatting surveillance using CertStream and AbuseIPDB. Optionnal sqlite database to store alerts.

## Introduction
The aim of this project is to establish a surveillance of the newly released/updated certificates using Certstream. A severity is then calculated based on the ressemblance of the domain names against the watched domain, the issuer of the certificate and the AbuseIPDB score of the IP of the domain.

## Configuration
The configuration file is json formated. The list of mandatory and optionnal parameters can be found in the following table :

Parameter | Mandatory ? | Description | Default
--- | --- | --- | ---
MY_DOMAIN | Yes | Domain to watch. | None
ABUSEIPDB_API_KEY | Yes | The AbuseIPDB api key. | None
CERTSTREAM_URL | Yes | The URL of the certstream server which will send the certificate events. | ws://localhost:8080
PRINT_LOGS | No | Boolean. All logs will be printed to the terminal if set to True. | false
LOG_LEVEL | No | The minimum level to log, it can be DEBUG, INFO, WARNING, ERROR or CRITICAL. | INFO
SUSPICIOUS_DOMAINS_FILE | No | The full path to the file in which the list of suspicious domains will be written. | suspicious_domains.log
LOG_FILE | No | The full path to the file in which the logs will be written. | typosquatting.log
MIN_RATIO | No | The minimum ratio (between 0 and 1) to raise an alert. | 0.7 
ABUSEIPDB_BASE_URL | No | AbuseIPDB api base URL | https://api.abuseipdb.com/api/v2
UNTRUSTED_ISSUERS | No | List of issuer that will be considered suspicious, example : ["Let's Encrypt"]. | []
HTTP_HEADERS | No | Headers that will be passed to the http calls. | {}
VERIFY_SSL | No | Do SSL certificate validation on HTTPS requests. Warning : Setting it to false is not recommanded for security reasons. | true



## Database
To interact with the sqlite database use the provided db_functions.py. In order to create the database and table, you **must** run the following command first:  
```python3 db_functions.py create_table```

The following db commands are available :
Command | Params | Description 
--- | --- | ---
create_table | No | Creates the alerts table
full_print | No | Prints the alerts table in full
last | No | Prints the last entry of the alerts table
last_10 | No | Prints the last 10 entries of the alerts table
search_by_domain | Domain_name | Search in the alerts table by exact domain name
search_by_level | Level (LOW, MEDIUM or HIGH) | Search in the alerts table by alert_level
delete_table | No | Deletes the alerts table

## Usage
- First, you should create the database and table as see in the [Database section](#Database), while this is not mandatory, it will be helpfull to access the alerts after.
- Create and fill the conf.json file. You can simply rename the sample_conf.json to conf.json and fill the ABUSEIPDB_API_KEY for a simple test.
- Install the required python packages:  
```pip install -r requirements.txt```

- Run the main script:  
```python3 main.py```

## Notes
Because the server provided by https://github.com/CaliDog/certstream-python (wss://certstream.calidog.io/) doesn't appear to be working anymore, I used https://github.com/d-Rickyy-b/certstream-server-go to get the certificate events instead. The client can then listen locally (ws://localhost:8080) for new events. This can be changed from the `CERTSTREAM_URL` parameter in the configuration file.
