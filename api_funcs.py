import requests
import sys
import ipaddress
import re
import pprint

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
        if res.status_code == 404:
            return (-1, 0, "0", 0)
        elif res.status_code != 200:
            raise Exception(f"Non standard status code {res.status_code} returned")
    except Exception as e:
        print(f"Couldn't get answer from virustotal for file hash\n{file_hash}", file=sys.stderr)
        print(e, file=sys.stderr)
        raise e
        
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
    else:
        print("Virustotal: clean", file=ostream)
    return

def printVTHash(file_hash, vt_api, ostream=sys.stdout):
    if vt_api != '' and re.match("^[A-Fa-f0-9]{4,64}$", file_hash):
        try:
            (malicious, total_vendors, date, positive_vendors) = virustotalHashData(file_hash, vt_api)
            if malicious == -1:
                print("Virustotal: unknown", file=ostream)
            else:
                printVTVerdict(malicious, total_vendors, date, positive_vendors, ostream=ostream)
                if malicious > 0:
                    print(f"https://www.virustotal.com/gui/file/{file_hash}", file=ostream)
        except:
            print("Exception caught while priting virustotal file hash", file=sys.stderr)
    return

def ipIsRemote(ip):
    if ipaddress.ip_address(ip) in ipaddress.ip_network('192.168.0.0/16') or ipaddress.ip_address(ip) in ipaddress.ip_network('10.0.0.0/8') or ipaddress.ip_address(ip) in ipaddress.ip_network('172.16.0.0/12') or ipaddress.ip_address(ip) in ipaddress.ip_network('169.254.0.0/16'):
        return False
    else:
        return True

def AbuseIPDBData(ip, api_key):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Key': api_key, 'Accept': 'application/json'}
    
    try:
        response = requests.get(url, params=params, headers=headers)
        return response.json()['data']
    except:
        print(f"Exception caught while getting AbuseIPDB data for {ip}", file=sys.stderr)
    return {}

def printIfNonempty(description, input_string, ostream=sys.stdout, **kwargs):
    if input_string != "" and input_string != "``":
        print(f"{description}: {input_string}", file=ostream, **kwargs)
    return

def printABIP(ip, api_key = '', ostream=sys.stdout):
    if api_key != '':
        result = AbuseIPDBData(ip, api_key)
        
        score = result['abuseConfidenceScore']
        if score == 0:
            print("AbuseIPDB: clean", file=ostream)
        elif score > 0:
            print(f"AbuseIPDB: {score}%", file=ostream)
            printIfNonempty("Country", result['countryCode'], ostream=ostream)
            printIfNonempty("ISP", result['isp'], ostream=ostream)
            printIfNonempty("Last report", result['lastReportedAt'], ostream=ostream)
            printIfNonempty("Type", result['usageType'], ostream=ostream)
            print(f"https://www.abuseipdb.com/check/{ip}", file=ostream)

# Takes a string of an IPv4 and puts [.] instead of . and quotes (`) around it.
def defangIP(ip):
    return f"`{ip.replace('.', '[.]')}`"

def printIPAnalysis(local_ip, remote_ip, vt_api = '', ab_api = '', ostream=sys.stdout):
    # Check that we have an api
    if vt_api == '' and ab_api == '':
        return
        
    # Check if at least one IP is remote
    if not (ipIsRemote(local_ip) or ipIsRemote(remote_ip)):
        return
    
    if ipIsRemote(local_ip):
        print(f"\nIP: {defangIP(local_ip)}", file=ostream)
        printVTIP(local_ip, vt_api, ostream=ostream)
        printABIP(local_ip, api_key = ab_api, ostream=ostream)
    if ipIsRemote(remote_ip):
        print(f"\nIP: {defangIP(remote_ip)}", file=ostream)
        printVTIP(remote_ip, vt_api, ostream=ostream)
        printABIP(remote_ip, api_key = ab_api, ostream=ostream)
    return

# Print VT analysis result of IP if it is not internal.
def printVTIP(ip, vt_api, ostream=sys.stdout):
    if vt_api != '':
        (malicious, total_vendors, date, positive_vendors) = virustotalIPData(ip, vt_api)
        printVTVerdict(malicious, total_vendors, date, positive_vendors, ostream=ostream)
        if malicious > 0:
            print(f"https://www.virustotal.com/gui/ip-address/{ip}", file=ostream)
        return
    return
    

# ChatGPT section
    
def getChatGPTAnswer(prompt, api_key, temp=0.24, best_of = 3, max_tokens = 300):
    endpoint = "https://api.openai.com/v1/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    # Define the payload
    data = '{' + f"""
    "model": "text-davinci-003",
    "prompt": "{prompt}",
    "temperature": {temp},
    "top_p": 1,
    "n": 1,
    "max_tokens": {max_tokens},
    "presence_penalty": 0,
    "frequency_penalty": 0,
    "best_of": {best_of}
""" + '}'
    try:
        # Make the API call
        response = requests.post(endpoint, headers=headers, data=data)
        if response.status_code == 400:
            error_message = response.json()['error']['message']
            raise Exception(f"ChatGPT endpoint {endpoint} returned error message: \n\n{error_message}\n\nafter sending payload:\n\n{data}")
        elif response.status_code != 200:
            pprint.pprint(response.json())
            raise Exception(f"ChatGPT endpoint {endpoint} returned unexpected status code: {response.status_code}")
        rd = response.json()
        choice = rd['choices'][0]
        return choice['text'].strip()
    except Exception as e:
        print(e, file=sys.stderr)
    except:
        print(f"ERROR when asking ChatGPT with prompt:\n{prompt}", file=sys.stderr)
    return ''

def printChatGPTProcess(process_name, api_key, ostream=sys.stdout):
    prompt = f"""The following is a conversation with the security researcher Steve Gibson from the podcast\\n\
Security Now!. Steve is intelligent and detail-oriented without giving overly long answers. In his answers,\\n\
he explains what the process is normally used for and who developed it. If the processes have high potentials for\\n\
misuse, he lists some of the most common ones and mentions if they are considered LOLBins.\\n\
\\n\
Q: chrome.exe\\n\
A: Chrome.exe is an executable used by Google Chrome, a web browser developed by Google. It is used\\n\
to manage the browser's memory and processes, as well as to render webpages. It is a legitimate process,\\n\
but it can be used for malicious purposes. The most common malicious uses of this process include hijacking\\n\
the browser, stealing user data, and installing malicious software.\\n\
\\n\
Q: SWwzzr67B42.exe\\n\
A: Unknown\\n\
\\n\
Q: obsidian.exe\\n\
A: Obsidian.exe is a process belonging to the Obsidian note-taking application. It is responsible for launching\\n\
and running the application and all its associated functions, such as note storage and retrieval, rendering\\n\
the user interface, and handling user interactions. Obsidian.exe is a legitimate process created by Obsidian,\\n\
a company known for its innovative note-taking software. It is not commonly associated with malicious activity or\\n\
targeted by cybercriminals.\\n\
\\n\
Q: cscript.exe\\n\
A: Cscript.exe is a legitimate process developed by Microsoft. It's commonly used as a command-line script\\n\
interpreter for running VBScript and JScript scripts. Cscript.exe allows scripts to be executed in a\\n\
command-line environment, making it a powerful tool for system administrators and software developers.\\n\
It's also used by malware authors as a way to execute malicious scripts on a victim's system.\\n\
Malware authors can use the process to execute malicious scripts that can install malware, steal sensitive\\n\
information, or take control of a victim's system. One common way that Cscript.exe is misused is by\\n\
injecting malicious scripts into legitimate files or documents. This is one of the reasons why it is included\\n\
in the list of common LOLbins used in Windows.\\n\
\\n\
Q: calc.exe\\n\
A: Calc.exe is a legitimate process developed by Microsoft that is commonly used as the Windows calculator\\n\
application. It's a simple tool that can perform basic arithmetic operations and conversions, making it useful\\n\
for a variety of tasks. Calc.exe is not typically associated with malicious activity, as it's not a commonly\\n\
exploited process for malware attacks.\\n\
\\n\
Q: vj89345tioadfuj890g54o45.flkds\\n\
A: Unknown\\n\
\\n\
Q: diskshadow.exe\\n\
A: Diskshadow.exe is a legitimate process developed by Microsoft. It is used to manage the Volume Shadow\\n\
Copy Service (VSS) on Windows systems. VSS is a feature of Windows that allows users to create snapshots\\n\
of their system, which can be used for backup and recovery purposes. Diskshadow.exe is used to manage\\n\
these snapshots and can be used to create, delete, and restore them. It is not commonly associated with\\n\
malicious activity, but it can be used by malware authors to create and restore malicious snapshots and is therefore\\n\
considered a LOLBin and listed in the LOLBAS project page.\\n\
\\n\
Q: {process_name}\\n\
A: """
    ans = getChatGPTAnswer(prompt, api_key)
    lines = ans.split("\n")
    for line in lines:
        print("> " + line, file=ostream)
    return

def printChatGPTAnswer(alert_dict, api_key, ostream=sys.stdout):
    if alert_dict['initiator_name'] != '':
        prompt = f"Explain what the process {alert_dict['initiator_name']} is commonly used for. Also give a possibly reason for how it could be linked to a security alert like `{alert_dict['alert_name']}`? Do not repeat the full text of the alert in your answer, only refer to it as 'the alert'."
        ans = getChatGPTAnswer(prompt, api_key)
        lines = ans.split("\n")
        for line in lines:
            print("> " + line, file=ostream)
    return