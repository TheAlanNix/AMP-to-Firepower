# AMP to Firepower

## Summary

This is a script to take attributes about a host from Cisco's AMP for Endpoints product, and import that data into Firepower Management Center.

Currently the imported attributes include the following:

- External IP
- Hostname
- Operating System
- AMP Connector Version
- AMP Isolation Status
- AMP Policy
- Discovered Vulnerabilities

## Requirements

If you wish to run this script locally, you'll need:

1. Python 3.x
2. Perl
3. OpenSSL

However, a Docker container has been built which contains all dependencies for this project, and is the cleanest and most secure way to run this script.

## Environment Variables

This script uses environment variables for configuration.  An example of the environment variables needed are in the ***.env.example*** file in the root of the repository.  The variables are defined as follows:

### AMP for Endpoints Configuration Parameters
- AMP_API_FQDN: (String) The FQDN of the AMP for Endpoints region to use. Available options:
  - api.amp.cisco.com
  - api.apjc.amp.cisco.com
  - api.eu.amp.cisco.com
- AMP_API_CLIENT_ID: (String) The AMP for Endpoints API Client ID
- AMP_API_KEY: (String) The AMP for Endpoints API Key
- AMP_API_LOAD_INTERVAL: (Integer) The refresh interval to use. Default: 3600

### Firepower Configuration Parameters
- FIREPOWER_FQDN: (String) The FQDN of the Firepower Management Center (FMC) to use.
- FIREPOWER_CERT_PASS: (String) The password for the pkcs12 certificate bundle. Default: null

## How-to Run

First, you'll need to allow Host Input API access within Firepower Management Center (FMC), and download the authentication certificate to use with this script.  To do this, access the FMC web interface and go to System -> Integration -> Host Input Client.

On the Host Input Client page, click on the "Create Client" button, then specify a hostname/IP for the client, and set a password if desired.

Once the client is created, download the pkcs12 certificate bundle from the FMC - this is what the script will use to authenticate to the FMC.

Next, make a copy of ***.env.example*** file as ***.env***.  From the project root directory, run the following:

>```cp .env.example .env```

Fill out the configuration variables in the ***.env*** file according to the documentation above.

### Docker Container

If you wish to run this script as a Docker container, you can execute the following command:

>```docker run --env-file <PATH_TO_ENV_FILE> --volume <PATH_TO_PKCS12>:/app/HostInputSDK/cert.pkcs12 alannix/amp-to-firepower```

This will download the container image from Docker Hub and run with the appropriate environment variables and certificate.

### Local Execution

If running this script locally, you'll need to install the required packages from the ***requirements.txt*** file.
  * You'll probably want to set up a virtual environment: [Python 'venv' Tutorial](https://docs.python.org/3/tutorial/venv.html)
    * Activate the Python virtual environment, if you created one.
    * ```pip install -r requirements.txt```
  * Place the PKCS12 file in the HostInputSDK directory.
  * Run the script with ```python amp_to_firepower.py```
