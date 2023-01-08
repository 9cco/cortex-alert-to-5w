import os
import re
import sys

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

   
def generateAlertDictionary(alert_string):

    try:
        pattern = "^([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t([^\t]*)\t"
        match_object = re.search(pattern, alert_string)
        
        alert_id = match_object.expand(r"\g<1>")
        timestamp = match_object.expand(r"\g<2>")
        host = match_object.expand(r"\g<3>")
        host_ip = match_object.expand(r"\g<4>")
        host_os = match_object.expand(r"\g<5>")
        username = match_object.expand(r"\g<6>")
        action = match_object.expand(r"\g<10>")
        alert_source = match_object.expand(r"\g<9>")
        alert_name = match_object.expand(r"\g<12>")
        description = match_object.expand(r"\g<13>")
        initiator_cmd = match_object.expand(r"\g<20>")
        initiator_sha256 = match_object.expand(r"\g<21>")
        initiator_signature = match_object.expand(r"\g<24>")
        CGO_cmd = match_object.expand(r"\g<27>")
        CGO_sha256 = match_object.expand(r"\g<29>")
        CGO_signature = match_object.expand(r"\g<32>")
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
        app_id = match_object.expand(r"\g<50>")
        source_zone = match_object.expand(r"\g<65>")
        dest_zone = match_object.expand(r"\g<65>")
        url = match_object.expand(r"\g<72>")
        email_subject = match_object.expand(r"\g<73>")
        email_sender = match_object.expand(r"\g<74>")
        email_recipient = match_object.expand(r"\g<75>")
        misc = match_object.expand(r"\g<81>")
        domain = match_object.expand(r"\g<84>")
        module = match_object.expand(r"\g<86>")
        dns_query = match_object.expand(r"\g<88>")
        user_agent = match_object.expand(r"\g<88>")

        alert_dict = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "host": host,
            "host_ip": host_ip,
            "host_os": host_os,
            "username": username,
            "action": action,
            "alert_source": alert_source,
            "alert_name": alert_name,
            "description": description,
            "initiator_cmd": initiator_cmd,
            "initiator_sha256": initiator_sha256,
            "initiator_signature": initiator_signature,
            "cgo_cmd": CGO_cmd,
            "cgo_sha256": CGO_sha256,
            "cgo_signature": CGO_signature,
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
            "app_id": app_id,
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
    except:
        eprint("Could not generate dictionary")
        exit(2)
        
    return alert_dict    

def printIfNonempty(description, input_string, ostream=sys.stdout, **kwargs):
    if input_string != "":
        print(f"{description}: {input_string}", file=ostream, **kwargs)
    return

def printReport(alert_dict, ostream=sys.stdout):

    # Title section
    print("\n=============================================================================\n\n", file=ostream)
    
    # Who section
    print("Who:  \n-----------------------------------------------------------------------------  \n", file=ostream)
    printIfNonempty("User", alert_dict['username'], ostream=ostream)
    if alert_dict["username"] != "" and (alert_dict['host'] != "" or alert_dict['host_ip'] != ''):
        print("", file=ostream)
    printIfNonempty("Host", alert_dict['host'], ostream=ostream)
    printIfNonempty("Host IP", alert_dict['host_ip'], ostream=ostream)
        
    # Where section
    print("\n\nWhere:  \n-----------------------------------------------------------------------------  \n", file=ostream)
    if alert_dict['source_zone'] != "" and alert_dict['dest_zone'] != "":
        print(f"From {alert_dict['source_zone']} to {alert_dict['dest_zone']}", file=ostream)
    printIfNonempty("Domain", alert_dict['domain'], ostream=ostream)
    
    # What section
    print("\n\nWhat:  \n-----------------------------------------------------------------------------  \n", file=ostream)
    printIfNonempty("Alert name", alert_dict['alert_name'], ostream=ostream)
    if not re.match(r"^\[ocd-xdr.*", alert_dict['alert_name']):
        printIfNonempty("Description", alert_dict['description'], ostream=ostream)
    
    if alert_dict['action'] != "":
        print("", file=ostream)
    
    printIfNonempty("Action", alert_dict['action'], ostream=ostream)
    printIfNonempty("Alert source", alert_dict['alert_source'], ostream=ostream)
    printIfNonempty("Module", alert_dict['module'], ostream=ostream)
        
    if alert_dict['initiator_cmd'] != '':
        print("", file=ostream)
        print("Initiator details:", file=ostream)
        print(f"Command: `{alert_dict['initiator_cmd']}`", file=ostream)
        printIfNonempty("SHA256", alert_dict['initiator_sha256'], ostream=ostream)
        printIfNonempty("Signer", alert_dict['initiator_signature'], ostream=ostream)
    
    if alert_dict['cgo_cmd'] != '':
        print("", file=ostream)
        print("Causality group owner details:", file=ostream)
        print(f"Command: `{alert_dict['cgo_cmd']}`", file=ostream)
        printIfNonempty("SHA256", alert_dict['cgo_sha256'], ostream=ostream)
        printIfNonempty("Signer", alert_dict['cgo_signature'], ostream=ostream)
    
    if alert_dict['target_process_cmd'] != '':
        print("", file=ostream)
        print("Target process details:", file=ostream)
        print(f"Command: `{alert_dict['target_process_cmd']}`", file=ostream)
        printIfNonempty("SHA256", alert_dict['target_process_sha256'], ostream=ostream)
        printIfNonempty("Signer", alert_dict['target_process_signature'], ostream=ostream)
    
    if alert_dict['file_path'] != '':
        print("", file=ostream)
        print("File details:", file=ostream)
        printIfNonempty("Path", alert_dict['file_path'], ostream=ostream)
        printIfNonempty("SHA256", alert_dict['file_sha256'], ostream=ostream)
    
    printIfNonempty("Macro SHA256", alert_dict['file_macro_sha256'], ostream=ostream)
    
    if alert_dict['registry_data'] != '':
        print("", file=ostream)
        print("Registry details:", file=ostream)
        printIfNonempty("Key", alert_dict['registry_key'], ostream=ostream)
        printIfNonempty("Data", alert_dict['registry_data'], ostream=ostream)
        
    if alert_dict['remote_ip'] != '':
        print("", file=ostream)
        print(f"Network connection: {alert_dict['local_ip']}:{alert_dict['local_port']} --> {alert_dict['remote_ip']}:{alert_dict['remote_port']}    ({alert_dict['app_id']})")
        printIfNonempty("Key", alert_dict['registry_key'], ostream=ostream)
        
    if alert_dict['email_subject'] != '':
        print("", file=ostream)
        print("Email details:", file=ostream)
        printIfNonempty("Subject", alert_dict['email_subject'], ostream=ostream)
        printIfNonempty("From", alert_dict['email_sender'], ostream=ostream)
        printIfNonempty("To", alert_dict['email_recipient'], ostream=ostream)
    
    printIfNonempty("URL", alert_dict['url'], ostream=ostream)
    printIfNonempty("User agent", alert_dict['user_agent'], ostream=ostream)
    printIfNonempty("Misc", alert_dict['misc'], ostream=ostream)
    printIfNonempty("DNS query", alert_dict['dns_query'], ostream=ostream)
    
    # Why section
    print("\n\nWhy:  \n-----------------------------------------------------------------------------  \n\n", file=ostream)
    
    # When section
    print("\n\nWhen:  \n-----------------------------------------------------------------------------  \n", file=ostream)
    if alert_dict['timestamp'] != '':
        print(alert_dict['timestamp'] + " UTC", file=ostream)
    
    # Footer section
    print("\n\n\n_____________________________________________________________________________", file=ostream)
    print("# Other notes\n\nSearching\n```XQL\n```", file=ostream)