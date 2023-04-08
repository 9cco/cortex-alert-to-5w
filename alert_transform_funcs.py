import os
import re
import sys

from api_funcs import printVTHash, printIPAnalysis, ipIsRemote, printChatGPTAnswer, printChatGPTProcess

# Function for printing to stderr
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def readFile(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            alert_string = file.read()
        return alert_string
    else:
        eprint("Could not find the file at:" + path)
        exit(2)

def defang(domain_string):
    # Separate out the domains from the string.
    match_object = re.match("^(.*?)([\w\-]+)\.([\w\-]+)\.([\w\-]+)((?:\.[\w\-]+){0,})([\w\-/]+\.[\w]+[\w\-?=/&]*)?(.*)$", domain_string)
    if match_object:
        return match_object.expand(r'\1`\2[.]\3[.]\4\5\6`\7')
    else:
        return  domain_string
   
def generateAlertDictionary(alert_string):

    try:
        pattern = "^([^\t]*)\t([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?([^\t]*)\t?"
        match_object = re.search(pattern, alert_string)
        assert (match_object != None), "Did not find any matches of regular expression"
        
        alert_id = match_object.expand(r"\g<1>")
        timestamp = match_object.expand(r"\g<2>")
        host = match_object.expand(r"\g<3>")
        host_ip = match_object.expand(r"\g<4>")
        host_os = match_object.expand(r"\g<5>")
        username = match_object.expand(r"\g<6>")
        incident_id = match_object.expand(r"\g<9>")
        alert_source = match_object.expand(r"\g<10>")
        action = match_object.expand(r"\g<11>")
        alert_name = match_object.expand(r"\g<13>")
        description = match_object.expand(r"\g<14>")
        initiator_name = match_object.expand(r"\g<16>")
        initiator_cmd = match_object.expand(r"\g<20>")
        initiator_sha256 = match_object.expand(r"\g<21>")
        initiator_signature = match_object.expand(r"\g<24>")
        CGO_name = match_object.expand(r"\g<26>")
        CGO_cmd = match_object.expand(r"\g<27>")
        CGO_sha256 = match_object.expand(r"\g<29>")
        CGO_signature = match_object.expand(r"\g<32>")
        target_process_name = match_object.expand(r"\g<34>")
        target_process_cmd = match_object.expand(r"\g<35>")
        target_process_sha256 = match_object.expand(r"\g<38>")
        target_process_signature = match_object.expand(r"\g<37>")
        file_path = match_object.expand(r"\g<39>")
        file_sha256 = match_object.expand(r"\g<42>")
        file_macro_sha256 = match_object.expand(r"\g<40>")
        registry_data = match_object.expand(r"\g<43>")
        registry_key = match_object.expand(r"\g<44>")
        local_ip = match_object.expand(r"\g<45>")
        local_port = match_object.expand(r"\g<46>")
        remote_ip = match_object.expand(r"\g<47>")
        remote_port = match_object.expand(r"\g<48>")
        remote_host = match_object.expand(r"\g<49>")
        app_id = match_object.expand(r"\g<50>")
        os_sub_type = match_object.expand(r"\g<64>")
        source_zone = match_object.expand(r"\g<65>")
        dest_zone = match_object.expand(r"\g<66>")
        url = match_object.expand(r"\g<72>")
        email_subject = match_object.expand(r"\g<73>")
        email_sender = match_object.expand(r"\g<74>")
        email_recipient = match_object.expand(r"\g<75>")
        misc = match_object.expand(r"\g<81>")
        domain = match_object.expand(r"\g<84>")
        module = match_object.expand(r"\g<86>")
        dns_query = match_object.expand(r"\g<88>")
        user_agent = match_object.expand(r"\g<103>")

        alert_dict = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "host": host,
            "host_ip": host_ip,
            "host_os": host_os,
            "username": username,
            "incident_id": incident_id,
            "action": action,
            "alert_source": alert_source,
            "alert_name": alert_name,
            "description": description,
            "initiator_name": initiator_name,
            "initiator_cmd": initiator_cmd,
            "initiator_sha256": initiator_sha256,
            "initiator_signature": initiator_signature,
            "cgo_name": CGO_name,
            "cgo_cmd": CGO_cmd,
            "cgo_sha256": CGO_sha256,
            "cgo_signature": CGO_signature,
            "target_process_name": target_process_name,
            "target_process_cmd": target_process_cmd,
            "target_process_sha256": target_process_sha256,
            "target_process_signature": target_process_signature,
            "file_path": file_path,
            "file_sha256": file_sha256,
            "file_macro_sha256": file_macro_sha256,
            "registry_data": registry_data,
            "registry_key": registry_key,
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "remote_host": remote_host,
            "app_id": app_id,
            "os_sub_type": os_sub_type,
            "source_zone": source_zone,
            "dest_zone": dest_zone,
            "url": url,
            "email_subject": email_subject,
            "email_sender": email_sender,
            "email_recipient": email_recipient,
            "misc": misc,
            "domain": domain,
            "module": module,
            "dns_query": dns_query,
            "user_agent": user_agent
        }
        
    except Exception as e:
        eprint(e)
        exit(2)
    except:
        eprint(f"Could not generate dictionary for alert string: \n{alert_string}")
        exit(2)
        
    return alert_dict    

def printIfNonempty(description, input_string, ostream=sys.stdout, **kwargs):
    if input_string != "" and input_string != "``":
        print(f"{description}: {input_string}", file=ostream, **kwargs)
    return

def printHostIP(ip_string, ostream=sys.stdout):
    if ip_string == "":
        return
    else:
        print("Host IP: ", end="", file=ostream)
        # If there are multiple IPs, the string will contain a ","
        if re.match(r"^(.*),(.*)$", ip_string):
            print(re.sub(",", ", ", ip_string), file=ostream)
        else:
            print(ip_string, file=ostream)
        return

def formatZones(string):
    split_string = string.split(',')
    # Check if string only contains duplicates
    if [split_string[0]]*len(split_string) == split_string:
        return split_string[0]
    # If normal string: make some space between commas.
    elif len(split_string) > 0:
        return re.sub(r',([^,])', r', \1', source_zone)
    else:
        return string

# Takes an IPv4 address as a string and returns a bool on whether or not the IP is internal or external.
def isInternalIP(ip_address):
    return not ipIsRemote(ip_address)
    #if re.match(r"^[^0-9]*10\.[0-9]+\.[0-9]+\.[0-9]+", ip_address) or re.match(r"^[^0-9]*192\.168\.[0-9]+\.[0-9]+", ip_address) or re.match(r"^[^0-9]*172\.(?:1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+", ip_address) or re.match(r"^[^0-9]*169\.254\.[0-9]+\.[0-9]+", ip_address):
    #    return True
    #return False

def printWhere(host, local_ip, remote_ip, source_zone, dest_zone, domain, ostream=sys.stdout):
    if source_zone != "" and dest_zone != "":
        source_zone = formatZones(source_zone)
        dest_zone = formatZones(dest_zone)
        print(f"From {source_zone} to {dest_zone}", file=ostream)
    elif domain != "" and domain != "``":
        print(f"Domain: {domain}", file=ostream)
    elif domain == "" and source_zone == "" and dest_zone == "" and host != "" and remote_ip == "":
        print("Internal endpoint w/ agent installed", file=ostream)
    # Attempt to recognize category of assets
    elif local_ip != "" and remote_ip != "":
        if isInternalIP(local_ip) and isInternalIP(remote_ip):
            print("Internal network assets", file=ostream)
        elif not isInternalIP(local_ip) and not isInternalIP(remote_ip):
            print("WAN", file=ostream)
        else:
            print("From ", end="", file=ostream)
            if isInternalIP(local_ip):
                print("Internal network", end="", file=ostream)
            else:
                print("WAN", end="", file=ostream)
            print(" to ", end="", file=ostream)
            if isInternalIP(remote_ip):
                print("Internal endpoint", file=ostream)
            else:
                print("WAN", file=ostream)
    return

def hasCommonName(ps_name):
    common_names = '''
explorer.exe
iexplore.exe
winlogon.exe
chrome.exe 
edge.exe
firefox.exe
outlook.exe
sh
bash
cmd.exe
powershell.exe
whoami.exe
'''
    name_lines = common_names.split('\n')
    if ps_name.lower() in name_lines:
        return True
    return False
    
def hasCommonSignature(ps_signature):
    common_signatures = '''
Microsoft Corporation
Google LLC
'''
    signature_lines = common_signatures.split('\n')
    if ps_signature in signature_lines:
        return True
    return False

def isTrustedProcess(ps_name, ps_signature):
    if (hasCommonName(ps_name) and ps_signature != "") or hasCommonSignature(ps_signature):
        return True
    return False

def printReport(alert_dict, vt_api = '', ab_api = '', ch_api = '', conf_dict={}, ostream=sys.stdout):

    # Title section
    print(f" | ID-{alert_dict['incident_id']}", file=ostream)
    print("=============================================================================\n\n", file=ostream)
    
    # Who section
    print("Who:  \n-------------------------------------------  \n", file=ostream)
    printIfNonempty("User", alert_dict['username'], ostream=ostream)
    if alert_dict["username"] != "" and (alert_dict['host'] != "" or alert_dict['host_ip'] != ''):
        print("", file=ostream)
    printIfNonempty("Host", alert_dict['host'], ostream=ostream)
    printHostIP(alert_dict['host_ip'], ostream=ostream)
    if not re.match(r"^.*Windows.*$", alert_dict['host_os']) and alert_dict['host_os'] != "N/A":
        if alert_dict['host_os'] != "":
            print(f"OS: {alert_dict['host_os']}", end="", file=ostream)
            if alert_dict['os_sub_type'] != "":
                print(f" ({alert_dict['os_sub_type']})", file=ostream)
            else:
                print("", file=ostream)
    
    # Where section
    print("\n\nWhere:  \n-------------------------------------------  \n", file=ostream)
    printWhere(alert_dict['host'], alert_dict['local_ip'], alert_dict['remote_ip'], alert_dict['source_zone'], alert_dict['dest_zone'], alert_dict['domain'], ostream=ostream)
    
    # What section
    print("\n\nWhat:  \n-------------------------------------------  \n", file=ostream)
    printIfNonempty("Alert name", defang(alert_dict['alert_name']), ostream=ostream)
    if not re.match(r"^\[ocd-xdr.*", alert_dict['alert_name']):
        printIfNonempty("Description", defang(alert_dict['description']), ostream=ostream)
    
    if alert_dict['action'] != "":
        print("", file=ostream)
    
    printIfNonempty("Action", alert_dict['action'], ostream=ostream)
    printIfNonempty("Alert source", alert_dict['alert_source'], ostream=ostream)
    printIfNonempty("Module", alert_dict['module'], ostream=ostream)
    
    # # Processes subsection
    if alert_dict['initiator_cmd'] != '':
        print("", file=ostream)
        print("Initiator details:", file=ostream)
        print(f"Command: `{alert_dict['initiator_cmd']}`", file=ostream)
        file_hash = alert_dict['initiator_sha256']
        printIfNonempty("SHA256", file_hash, ostream=ostream)
        printIfNonempty("Signer", alert_dict['initiator_signature'], ostream=ostream)
        if not isTrustedProcess(alert_dict['initiator_name'], alert_dict['initiator_signature']):
            printVTHash(file_hash, vt_api, ostream=ostream)
        if not hasCommonName(alert_dict['initiator_name']):
            print("", file=ostream)
            printChatGPTProcess(alert_dict['initiator_name'], ch_api, ostream=ostream)
        
    
    if alert_dict['cgo_cmd'] != '':
        print("", file=ostream)
        print("Causality group owner details:", file=ostream)
        if alert_dict['cgo_cmd'] != alert_dict['initiator_cmd']:
            print(f"Command: `{alert_dict['cgo_cmd']}`", file=ostream)
            file_hash = alert_dict['cgo_sha256']
            printIfNonempty("SHA256", file_hash, ostream=ostream)
            printIfNonempty("Signer", alert_dict['cgo_signature'], ostream=ostream)
            if not isTrustedProcess(alert_dict['cgo_name'], alert_dict['cgo_signature']):
                printVTHash(file_hash, vt_api, ostream=ostream)
            if not hasCommonName(alert_dict['cgo_name']) and alert_dict['cgo_name'] != alert_dict['initiator_name']:
                print("", file=ostream)
                printChatGPTProcess(alert_dict['cgo_name'], ch_api, ostream=ostream)
        else:
            print("Same as initiator.", file=ostream)
    
    if alert_dict['target_process_cmd'] != '':
        print("", file=ostream)
        print("Target process details:", file=ostream)
        print(f"Command: `{alert_dict['target_process_cmd']}`", file=ostream)
        file_hash = alert_dict['target_process_sha256']
        printIfNonempty("SHA256", file_hash, ostream=ostream)
        printIfNonempty("Signer", alert_dict['target_process_signature'], ostream=ostream)
        if not isTrustedProcess(alert_dict['target_process_name'], alert_dict['target_process_signature']):
            printVTHash(file_hash, vt_api, ostream=ostream)
        if not alert_dict['target_process_name'] in [alert_dict['initiator_name'], alert_dict['cgo_name']] and not hasCommonName(alert_dict['target_process_name']) :
            print("", file=ostream)
            printChatGPTProcess(alert_dict['target_process_name'], ch_api, ostream=ostream)
    
    # # File subsection
    if alert_dict['file_path'] != '':
        print("", file=ostream)
        print("File details:", file=ostream)
        printIfNonempty("Path", alert_dict['file_path'], ostream=ostream)
        file_hash = alert_dict['file_sha256']
        printIfNonempty("SHA256", file_hash, ostream=ostream)
        printVTHash(file_hash, vt_api, ostream=ostream)
    
    printIfNonempty("Macro SHA256", alert_dict['file_macro_sha256'], ostream=ostream)
    
    # # Registry subsection
    if alert_dict['registry_data'] != '':
        print("", file=ostream)
        print("Registry details:", file=ostream)
        printIfNonempty("Key", alert_dict['registry_key'], ostream=ostream)
        printIfNonempty("Data", alert_dict['registry_data'], ostream=ostream)
    
    # # Network connection subsection
    if alert_dict['remote_ip'] != '':
        print("", file=ostream)
        print(f"Network connection: {alert_dict['local_ip']}:{alert_dict['local_port']} --> {alert_dict['remote_ip']}:{alert_dict['remote_port']}    ({alert_dict['app_id']}", file=ostream, end="")
        
        if alert_dict['remote_host'] != '':
            if isInternalIP(alert_dict['remote_ip']):
                remote_host = alert_dict['remote_host']
            else:
                remote_host = defang(alert_dict['remote_host'])
            print(f", {remote_host})", file=ostream)
        else:
            print(")", file=ostream)
            
        printIPAnalysis(alert_dict['local_ip'], alert_dict['remote_ip'], vt_api = vt_api, ab_api = ab_api, ostream=ostream)
    
    # # Email subsection
    if alert_dict['email_subject'] != '':
        print("", file=ostream)
        print("Email details:", file=ostream)
        printIfNonempty("Subject", alert_dict['email_subject'], ostream=ostream)
        printIfNonempty("From", alert_dict['email_sender'], ostream=ostream)
        printIfNonempty("To", alert_dict['email_recipient'], ostream=ostream)
    
    url = ""
    if alert_dict['url'] != "":
        if isInternalIP(alert_dict['remote_ip']):
            url = alert_dict['url']
        else:
            url = defang(alert_dict['url'])
    printIfNonempty("URL", url, ostream=ostream)
    printIfNonempty("User agent", alert_dict['user_agent'], ostream=ostream)
    printIfNonempty("Misc", defang(alert_dict['misc']), ostream=ostream)
    printIfNonempty("DNS query", defang(alert_dict['dns_query']), ostream=ostream)
    
    # Why section
    print("\n\nWhy:  \n-------------------------------------------  \n", file=ostream)
    
    printChatGPTAnswer(alert_dict, ch_api, ostream=ostream)
    
    # When section
    print("\n\nWhen:  \n-------------------------------------------  \n", file=ostream)
    if alert_dict['timestamp'] != '':
        print(alert_dict['timestamp'] + " UTC", file=ostream)
    
    # Footer section
    print("\n\n\n_____________________________________________________________________________", file=ostream)
    print("# Other notes\n\nSearching\n```XQL\n```", file=ostream)
    
def getDay(timestamp):
    match_object = re.search("([0-9]{1,2})[^0-9]{2}", timestamp)
    return match_object.expand(r"\g<1>")
    