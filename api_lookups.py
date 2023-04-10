import asyncio
import aiohttp
import re
import sys
import textwrap

from aux_functions import isTrustedProcess, hasCommonName, returnIfNonempty, matchesAnyOne, ipIsRemote

def searchCredential(credentials, search_string):
    for cred in credentials:
        if cred.name == search_string:
            return cred.data
    raise Exception(f"searchCredential ERROR: Could not find {search_string} in credentials.")

def separateCredentials(credentials):
    vt_api = searchCredential(credentials, "virustotal_api_key")
    ab_api = searchCredential(credentials, "abuseipdb_api_key")
    ch_api = searchCredential(credentials, "chatgpt_api_key")
    
    return vt_api, ab_api, ch_api

# Returns the number of vendors rating it as malicious, the total number of vendors,
# the date the analysis was done and a list of the vendor-names reporting the file as malicious.
async def virustotalHashData(session, file_hash, api_key):
    try:
        headers = { "x-apikey": api_key }
        res = await session.get(url=f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)

        res_dict = await res.json()
        code = res.status
        if code == 404:
            return (-1, 0, "0", 0)
        elif code != 200:
            raise Exception(f"Non standard status code {code} returned")
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

def formatVTVerdict(malicious, total_vendors, date, positive_vendors):
    if malicious > 0:
        return f"Virustotal: {malicious}/{total_vendors}"
    else:
        return "Virustotal: clean"
    return

async def virustotalHashReport(session, file_hash, vt_api, id):
    report = ' '
    
    if vt_api != '' and re.match("^[A-Fa-f0-9]{4,64}$", file_hash):
        try:
            (malicious, total_vendors, date, positive_vendors) = await virustotalHashData(session, file_hash, vt_api)
            if malicious == -1:
                report = "Virustotal: unknown"
            else:
                report = formatVTVerdict(malicious, total_vendors, date, positive_vendors)
                if malicious > 0:
                    report += "\n" + f"https://www.virustotal.com/gui/file/{file_hash}"
        except:
            print("Exception caught while printing virustotal file hash", file=sys.stderr)
    else:
        raise Exception(f"virustotalHashReport ERROR: File hash '{file_hash}' is not a file hash")
    return id, report

async def getChatGPTAnswer(session, prompt, api_key, temp=0.24, best_of = 3, max_tokens = 300):
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
        response = await session.post(endpoint, headers=headers, data=data)
        code = response.status
        response_data = await response.json()
        if code == 400:
            error_message = response_data['error']['message']
            raise Exception(f"ChatGPT endpoint {endpoint} returned error message: \n\n{error_message}\n\nafter sending payload:\n\n{data}")
        elif code != 200:
            print(response_data)
            raise Exception(f"ChatGPT endpoint {endpoint} returned unexpected status code: {code}")
        rd = response_data
        choice = rd['choices'][0]
        return choice['text'].strip()
    except Exception as e:
        print(e, file=sys.stderr)
    except:
        print(f"ERROR when asking ChatGPT with prompt:\n{prompt}", file=sys.stderr)
    return ''

def formatChatGPTAnswer(ans):
    wrapped_lines = textwrap.wrap(ans, width=60)
    formatted = ''
    for line in wrapped_lines:
        formatted += "> " + line + "\n"
    
    return formatted

async def chatGPTProcessReport(session, process_name, api_key, settings_dict, id_string):
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
    ans = await getChatGPTAnswer(session, prompt, api_key)
    report = formatChatGPTAnswer(ans)
    return id_string, report

# Add a async tasks to the tasks list related to a process. This includes a Virustotal, and a chatGPT lookup.
async def addProcessTask(session, tasks, prev_processes, ps_name, ps_sha256, ps_sign, settings_dict, vt_api, ch_api, id_prefix, use_chat = True):
    if ps_name != '' and ps_name not in prev_processes:
        prev_processes.append(ps_name)
        if not isTrustedProcess(ps_name, ps_sign, settings_dict):
            task_id = id_prefix + "_vt"
            task = asyncio.create_task(virustotalHashReport(session, ps_sha256, vt_api, task_id))
            tasks.append(task)
        if not hasCommonName(ps_name, settings_dict['common-process-names']) and use_chat:
            task_id = id_prefix + "_ch"
            task = asyncio.create_task(chatGPTProcessReport(session, ps_name, ch_api, settings_dict, task_id))
            tasks.append(task)
    return

# Counts the number of vendors considering the ip as malicious and creates a report of this. Returns the id_string as well as
# the report as a tuple.
async def virustotalIPReport(session, ip, api_key, id_string):
    try:
        headers = { "x-apikey": api_key }
        res = await session.get(url=f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers)

        res_dict = await res.json()
    except Exception as e:
        print("Couldn't get answer from virustotal", file=sys.stderr)
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
    
    # Creates a list of vendors that counts the ip as malicious.
#    positive_vendors = []
#    if malicious > 0:
#        keys = last_results.keys()
#        for key in keys:
#            if last_results[key]['result'] not in ['clean', 'unrated'] :
#                positive_vendors.append(key)
    
    # Create report
    if malicious > 0:
        report = f"Virustotal: {malicious}/{total_vendors}\n https://www.virustotal.com/gui/ip-address/{ip}"
    else:
        report = "Virustotal: clean"
    
    return id_string, report

async def abusedIPReport(session, ip, api_key, id_string):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Key': api_key, 'Accept': 'application/json'}
    
    try:
        response = await session.get(url, params=params, headers=headers)
        aux = await response.json()
        data = aux['data']
    except:
        print(f"Exception caught while getting AbuseIPDB data for {ip}", file=sys.stderr)
    
    # Generate report from data
    score = data['abuseConfidenceScore']
    if score == 0:
        report = "AbuseIPDB: clean"
    elif score > 0:
        report = f"AbuseIPDB: {score}%\n"
        report += returnIfNonempty("Country", data['countryCode'])
        report += returnIfNonempty("ISP", data['isp'])
        report += returnIfNonempty("Last report", data['lastReportedAt'])
        report += returnIfNonempty("Type", data['usageType'])
        report += f"https://www.abuseipdb.com/check/{ip}"
    
    return id_string, report
    
async def addIPReportTasks(session, tasks, ip, vt_api, ab_api, id_prefix):
    if ip != '' and ipIsRemote(ip):
            vt_task = asyncio.create_task(virustotalIPReport(session, ip, vt_api, id_prefix + "_vt"))
            tasks.append(vt_task)
            ab_task = asyncio.create_task(abusedIPReport(session, ip, ab_api, id_prefix + "_ab"))
            tasks.append(ab_task)
    return
    
def containsSensitiveInformation(infos, searches):
    for info in infos:
        if matchesAnyOne(searches, info):
            print(f"Warning: found sensitive information in '{info}'. Will not send anything to chatGPT.")
            return True
    return False
    
# Go through all information that will be sent to chat GPT and make the user verify that the information can be sent to chat GPT
def verifyChatGPTUsage(alert_dict, settings_dict):
    if settings_dict['verify-outgoing']:
        # Gather all sending information:
        info_fields = [alert_dict['initiator_name'], alert_dict['cgo_name'], alert_dict['target_process_name'], alert_dict['alert_name']]
        
        if containsSensitiveInformation(info_fields, settings_dict['info-searches']):
            return False
        
        print("ChatGPT may be sent the following information:\n-------------------")
        for field in info_fields:
            if field != '':
                print(field)
        
        choice = input(f"-------------------\nConfirm that no sensitive information will be sent (y/n): ")
        if 'y' in choice.lower():
            return True
        else:
            return False
    else:
        return True

# Make all necessary API lookups in an asynchronous manner, then synchronize threads
# and return information in a dictionary for each API-lookup.
async def asyncAPILookups(alert_dict, settings_dict, credentials):
    
    # Separate credentials into variables
    vt_api, ab_api, ch_api = separateCredentials(credentials)
    
    # Determine use of chat GPT
    use_chat = verifyChatGPTUsage(alert_dict, settings_dict)
    
    # Setup connection pool
    async with aiohttp.ClientSession() as session:
        tasks = []
        
        # Determine if API calls are necessary, and if they are: add them to the tasks
        
        prev_processes = []
        
        # Initiator process
        await addProcessTask(session, tasks, prev_processes, alert_dict['initiator_name'], alert_dict['initiator_sha256'], alert_dict['initiator_signature'],\
            settings_dict, vt_api, ch_api, 'initiator', use_chat = use_chat)
        # CGO process
        await addProcessTask(session, tasks, prev_processes, alert_dict['cgo_name'], alert_dict['cgo_sha256'], alert_dict['cgo_signature'], settings_dict,\
            vt_api, ch_api, 'cgo', use_chat = use_chat)
        # Target process
        await addProcessTask(session, tasks, prev_processes, alert_dict['target_process_name'], alert_dict['target_process_sha256'],\
            alert_dict['target_process_signature'], settings_dict, vt_api, ch_api, 'target_process', use_chat = use_chat)
        
        # File check.
        if alert_dict['file_path'] != '':
            task = asyncio.create_task(virustotalHashReport(session, alert_dict['file_sha256'], vt_api, "file_vt"))
            tasks.append(task)
        
        # IP Reports
        await addIPReportTasks(session, tasks, alert_dict['local_ip'], vt_api, ab_api, "local_ip")
        await addIPReportTasks(session, tasks, alert_dict['remote_ip'], vt_api, ab_api, "remote_ip")
        
        # Why section
        if use_chat:
            task = asyncio.create_task(chatGPTWhy(session, ch_api, alert_dict))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
    
    return results

async def chatGPTWhy(session, api_key, alert_dict):
    id_string = "why_ch"
    
    if alert_dict['initiator_name'] != '':
        prompt = f"Explain what the process {alert_dict['initiator_name']} is commonly used for. Also give a possibly reason for how it could be linked to a security alert like `{alert_dict['alert_name']}`? Do not repeat the full text of the alert in your answer, only refer to it as 'the alert'."
        ans = await getChatGPTAnswer(session, prompt, api_key)
        report = formatChatGPTAnswer(ans)
        return id_string, report
        
    return id_string, ''
    

# Auxhillary function to run and return the asynchronous tasks
def makeAsyncAPILookups(alert_dict, settings_dict, credentials):
    results = asyncio.run(asyncAPILookups(alert_dict, settings_dict, credentials))
    
    # Turns the list into a dictionary and returns this
    return {key: value for key, value in results}