#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
This script is meant to gather AMP for Endpoints attributes about a host and import
those attributes into Firepower Management Center.
"""

import argparse
import csv
import json
import os
import re
import subprocess
import time

import requests
import amp_client

from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv()

amp = None
group_guids = []

DEBUG = False


def _get_computers():
    """A function to retrieve AMP computer data and return it as JSON"""

    print("Fetching AMP for Endpoints computers...")

    # Get the computers that have been at the internal IP
    response = amp.get_computers(group_guids=group_guids)

    if DEBUG:
        print(json.dumps(response, indent=4))

    return response


def _get_os_vendor(os_name: str):
    """A function to determine the OS Vendor from the OS"""

    if DEBUG:
        print(f"Resolving OS vendor for '{os_name}'...")

    os_name_list = os_name.lower().split(" ")

    if os_name_list[0] == "windows":
        return "Microsoft"
    if os_name_list[0] == "osx" or (os_name_list[0] == "os" and os_name_list[1] == "x"):
        return "Apple"

    return None


def _get_vulnerabilities(time_delta: int = 30):
    """A function to retrieve AMP vulnerability data and return it as JSON"""

    print(f"Fetching AMP for Endpoints vulnerabilities for the past {time_delta} days...")

    # Create a start time
    start_time = datetime.utcnow().replace(microsecond=0) - timedelta(time_delta)
    start_time = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Get all vulnerabilities since the start time
    response = amp.get_vulnerabilities(start_time=start_time, group_guid=group_guids)

    if DEBUG:
        print(json.dumps(response, indent=4))

    return response


def _alpha_spaces_only(string: str):
    """A function to strip a string of anything but alphanumerics and spaces."""

    pattern = re.compile(r'([^\s\w.-]|_)+')
    return pattern.sub('', string)


def main():
    """This is a function to run the main logic of the AMP-to-Firepower script."""

    # Open a CSV file for writing
    with open('endpoint_data.csv', 'w') as csv_file:

        csv_writer = csv.writer(csv_file, lineterminator='\n')

        csv_writer.writerow(['SetSource', 'AMP for Endpoints'])
        csv_writer.writerow(['AddHostAttribute', 'AMP External IP', 'text'])
        csv_writer.writerow(['AddHostAttribute', 'AMP Hostname', 'text'])
        csv_writer.writerow(['AddHostAttribute', 'AMP Isolation', 'text'])
        csv_writer.writerow(['AddHostAttribute', 'AMP Link', 'URL'])
        csv_writer.writerow(['AddHostAttribute', 'AMP Policy', 'text'])
        csv_writer.writerow(['AddHostAttribute', 'AMP Version', 'text'])

        computers = _get_computers()
        vulnerabilities = _get_vulnerabilities()

        # Iterate through each computer
        for computer in computers:

            # Iterate through each internal IP for the computer
            for internal_ip in computer['internal_ips']:

                # Iterate through the network addresses for the computer
                for network_address in computer['network_addresses']:

                    # Find the MAC associated with IP
                    if internal_ip == network_address['ip']:

                        if DEBUG:
                            print(f"Adding host for {internal_ip}...")

                        csv_writer.writerow(['AddHost', internal_ip, network_address['mac']])

                # If the computer has an OS
                if computer['operating_system']:

                    # Get the OS vendor
                    os_vendor = _get_os_vendor(computer['operating_system'])

                    # If we resolved a vendor, then set the OS
                    if os_vendor:

                        if DEBUG:
                            print(f"Setting operating system attribute to {os_vendor} for {internal_ip}...")

                        csv_writer.writerow(['SetOS', internal_ip, os_vendor, _alpha_spaces_only(computer['operating_system'])])
                    else:
                        print(f"Unable to resolve vendor for '{computer['operating_system']}'")

                # If the computer has a hostname
                if computer['external_ip']:

                    if DEBUG:
                        print(f"Setting external IP attribute to {computer['external_ip']} for {internal_ip}...")

                    csv_writer.writerow(['SetAttributeValue', internal_ip, 'AMP External IP', computer['external_ip']])

                # If the computer has a hostname
                if computer['hostname']:

                    if DEBUG:
                        print(f"Setting hostname attribute to {computer['hostname']} for {internal_ip}...")

                    csv_writer.writerow(['SetAttributeValue', internal_ip, 'AMP Hostname', _alpha_spaces_only(computer['hostname'])])

                # If the computer has an isolation status
                if computer['isolation']['status']:

                    if DEBUG:
                        print(f"Setting isolation status attribute to {computer['isolation']['status']} for {internal_ip}...")

                    csv_writer.writerow(['SetAttributeValue', internal_ip, 'AMP Isolation', computer['isolation']['status']])

                # If the computer has a link
                if computer['links']['computer']:

                    if DEBUG:
                        print(f"Setting link attribute to {computer['links']['computer']} for {internal_ip}...")

                    csv_writer.writerow(['SetAttributeValue', internal_ip, 'AMP Link', computer['links']['computer']])

                # If the computer has a policy name
                if computer['policy']['name']:

                    if DEBUG:
                        print(f"Setting policy attribute to {computer['policy']['name']} for {internal_ip}...")

                    csv_writer.writerow(['SetAttributeValue', internal_ip, 'AMP Policy', _alpha_spaces_only(computer['policy']['name'])])

                # If the computer has a version
                if computer['connector_version']:

                    if DEBUG:
                        print(f"Setting link attribute to {computer['connector_version']} for {internal_ip}...")

                    csv_writer.writerow(['SetAttributeValue', internal_ip, 'AMP Version', computer['connector_version']])

                vuln_id = 10000

                # Iterate through all dicovered vulns
                for vulnerability in vulnerabilities:

                    # Iterate through all computers that have the current vuln
                    for vulnerable_computer in vulnerability['computers']:

                        # Match the vulnerable GUID to the current GUID
                        if computer['connector_guid'] == vulnerable_computer['connector_guid']:

                            name = f"{vulnerability['application']} {vulnerability['version']}"

                            cve_string = ""
                            for cve in vulnerability['cves']:
                                cve_string += f" {cve['id']}"

                            csv_writer.writerow(["AddScanResult", internal_ip, "AMP for Endpoints", vuln_id,
                                                 None, None, name, None, f"cve_ids:{cve_string}", "bugtraq_ids:"])

                            vuln_id += 1

        # Do a ScanFlush at the end
        csv_writer.writerow(['ScanFlush'])

    # Import the data into the FMC
    pipe = subprocess.call(["./sf_host_input_agent.pl",
                            "-server={}".format(os.getenv("FIREPOWER_FQDN")),
                            "-password={}".format(os.getenv("FIREPOWER_CERT_PASS")),
                            "-plugininfo=../endpoint_data.csv",
                            "csv"],
                           cwd=f"{os.getcwd()}/HostInputSDK")


if __name__ == "__main__":

    # Set up an argument parser
    parser = argparse.ArgumentParser(description="A script to import AMP for Endpoints attributes into Firepower")
    parser.add_argument("-d", "--daemon", help="Run the script as a daemon", action="store_true")
    parser.add_argument("-g", "--groups", help="AMP Group GUIDs to import (comma separated)")
    parser.add_argument("-v", "--verbose", help="Run the script with debug logging", action="store_true")
    args = parser.parse_args()

    # Exit if AMP not configured
    if not os.getenv("AMP_API_CLIENT_ID") or not os.getenv("AMP_API_KEY"):
        print("AMP for Endpoints credentials haven't been configured... exiting.")
        exit(1)

    # Create an AMP API Client
    amp = amp_client.AmpClient(client_id=os.getenv("AMP_API_CLIENT_ID"),
                               api_key=os.getenv("AMP_API_KEY"))

    if args.verbose:
        DEBUG = True

    # Process the provided Group GUIDs
    if args.groups:
        try:
            # Split the provided Group GUIDS
            group_guids = args.groups.split(',')

            # Strip whitespace from all elements
            map(str.strip, group_guids)
        except Exception as err:
            print(f"Error parsing AMP Group GUIDs: {err}")
            exit()

    # Run as a daemon if requested
    if args.daemon:
        while True:
            main()
            interval = int(os.getenv("AMP_API_LOAD_INTERVAL", "3600"))
            print(f"Waiting {interval} seconds...")
            time.sleep(interval)
    else:
        main()
