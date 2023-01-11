import requests
import sys
import ipaddress

# Returns the number of vendors rating it as malicious, the total number of vendors,
# the date the analysis was done and a list of the vendor-names reporting the IP as malicious.
def virustotalIPData(ip, api_key):
    try:
        headers = { "x-apikey": api_key }
        res = requests.get(url=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)

        res_dict = res.json()
    except:
        print("Couldn't get answer from virustotal", file=sys.stderr)
        return
        
    last_results = res_dict['data']['attributes']['last_analysis_results']
    stats = res_dict['data']['attributes']['last_analysis_stats']
    if 'last_analysis_date' in res_dict['data']['attributes']:
        date = res_dict['data']['attributes']['last_analysis_date']
    else:
        date = 0
    
    harmless = stats['harmless']
    malicious = stats['malicious'] + stats['suspicious']
    undetected = stats['undetected']
    
    total_vendors = harmless + malicious + undetected
    
    positive_vendors = []
    if malicious > 0:
        keys = last_results.keys()
        for key in keys:
            if last_results[key]['result'] not in ['clean', 'unrated'] :
                positive_vendors.append(key)
    
    return (malicious, total_vendors, date, positive_vendors)
    
# Returns the number of vendors rating it as malicious, the total number of vendors,
# the date the analysis was done and a list of the vendor-names reporting the file as malicious.
def virustotalHashData(file_hash, api_key):
    try:
        headers = { "x-apikey": api_key }
        res = requests.get(url=f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)

        res_dict = res.json()
    except:
        print("Couldn't get answer from virustotal", file=sys.stderr)
        return
        
    last_results = res_dict['data']['attributes']['last_analysis_results']
    stats = res_dict['data']['attributes']['last_analysis_stats']
    
    if 'last_analysis_date' in res_dict['data']['attributes']:
        date = res_dict['data']['attributes']['last_analysis_date']
    else:
        date = 0
    
    harmless = stats['harmless']
    malicious = stats['malicious'] + stats['suspicious']
    undetected = stats['undetected']
    
    total_vendors = harmless + malicious + undetected
    
    positive_vendors = []
    if malicious > 0:
        keys = last_results.keys()
        for key in keys:
            if last_results[key]['result'] not in [None] :
                positive_vendors.append(key)
    
    return (malicious, total_vendors, date, positive_vendors)
    
def printVTVerdict(malicious, total_vendors, date, positive_vendors, ostream=sys.stdout):
    if malicious > 0:
        print(f"Virustotal: {malicious}/{total_vendors}", file=ostream)
    return

def printVTHash(file_hash, vt_api, ostream=sys.stdout):
    if vt_api != '':
        (malicious, total_vendors, date, positive_vendors) = virustotalHashData(file_hash, vt_api)
        printVTVerdict(malicious, total_vendors, date, positive_vendors, ostream=ostream)
    return

def ipIsRemote(ip):
    if ipaddress.ip_address(ip) in ipaddress.ip_network('192.168.0.0/16') or ipaddress.ip_address(ip) in ipaddress.ip_network('10.0.0.0/8') or ipaddress.ip_address(ip) in ipaddress.ip_network('172.16.0.0/12'):
        return False
    else:
        return True

# Print VT analysis result of IP if it is not internal.
def printVTIP(ip, vt_api, ostream=sys.stdout):
    if ipIsRemote(ip) and vt_api != '':
        (malicious, total_vendors, date, positive_vendors) = virustotalIPData(ip, vt_api)
        printVTVerdict(malicious, total_vendors, date, positive_vendors, ostream=ostream)
        return
    else:
        return
    