#!/usr/bin/python

import sys
import requests
import time

def submitScan(configId, headers):
    resp=requests.post("https://us.api.insight.rapid7.com/ias/v1/scans", 
        data='{{ "scan_config": {{ "id": "{}" }} }}'.format(configId), 
        headers=headers)
    resp.raise_for_status()
    scanUrl=resp.headers['Location']
    print("Scan submitted.  Tracking status via", scanUrl, flush=True)
    return scanUrl

def waitForScan(scanUrl, headers):
    status = 'IN PROGRESS'
    for tryCount in range(30):
        resp=requests.get(scanUrl, headers=headers)
        resp.raise_for_status()
        status=resp.json()['status']

        if status == 'COMPLETE':
           print("Scan Completed", flush=True)
           break
        elif status == 'FAILED':
           print("Scan failed", flush=True)
           break
        elif tryCount == 29:
           print("Last call. Giving it one more minute to complete before giving up.", flush=True)
        elif tryCount == 30:
           print("Giving up.", flush=True)
           break
        else:
           print("Waiting for scan to complete after", tryCount, "minutes. Status is", status, ". Sleeping for another 60 seconds...", flush=True)
           time.sleep(60)

def getScanResults(appId, headers):
    resp=requests.post("https://us.api.insight.rapid7.com/ias/v1/search", 
        data='''{{ 
                   "type": "VULNERABILITY", 
                   "query": "vulnerability.severity = 'MEDIUM' && vulnerability.status = 'UNREVIEWED' && vulnerability.app.id = '{}'"
                }}'''.format(appId),
        headers=headers)
    resp.raise_for_status()
    if resp.json()['metadata']['total_data'] > 0:
        sys.stderr.write(resp.json())
        return "FAILED security scan"
    else:
        return "No significant vulnerabilities found."

def printUsage():
   sys.stderr.write("Invalid syntax.\n")
   sys.stderr.write("USAGE: scan.py API_KEY APP_ID SCAN_CONFIG_ID")

if len(sys.argv) < 4:
   printUsage()
   raise SystemExit(1)

apiKey=sys.argv[1]
appId=sys.argv[2]
configId=sys.argv[3]
headers = {'X-Api-Key': apiKey, "Content-Type": "application/json"}
scan=submitScan(configId, headers)
waitForScan(scan, headers)
print(getScanResults(appId, headers), flush=True)