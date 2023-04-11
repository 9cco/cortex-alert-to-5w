import re

from aux_functions import returnIfNonempty, ipIsRemote
from xql_queries import generateXQLQuery

def writeTitle(incident_id):
    string = f" | ID-{incident_id}\n"
    string += "=============================================================================\n\n\n"
    return string

def formatIPString(ip_string, prefix = "Host IP: "):
    if ip_string == "":
        return ""
    else:
        string = prefix
        # If there are multiple IPs, the string will contain a ","
        if re.match(r"^(.*),(.*)$", ip_string):
            string += re.sub(",", ", ", ip_string) + "\n"
        else:
            string += ip_string + "\n"
        return string

# Who section
def writeWho(username, host, host_ip, host_os, os_sub_type):
    string = "Who:  \n-------------------------------------------  \n"
    string += returnIfNonempty("User", username)
    if username != "" and (host != "" or host_ip != ''):
        string += "\n"
    string += returnIfNonempty("Host", host)
    string += formatIPString(host_ip)
    if not re.match(r"^.*Windows.*$", host_os) and host_os != "N/A":
        if host_os != "":
            string += f"OS: {host_os}"
            if os_sub_type != "":
                string += f" ({os_sub_type})\n"
            else:
                string += "\n"
    return string

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

def isInternalIP(ip_address):
    return not ipIsRemote(ip_address)

def writeWhere(host, local_ip, remote_ip, source_zone, dest_zone, domain):
    string = ''
    if source_zone != "" and dest_zone != "":
        source_zone = formatZones(source_zone)
        dest_zone = formatZones(dest_zone)
        string += f"From {source_zone} to {dest_zone}\n"
    elif domain != "" and domain != "``":
        string += f"Domain: {domain}\n"
    elif domain == "" and source_zone == "" and dest_zone == "" and host != "" and remote_ip == "":
        string += "Internal endpoint w/ agent installed\n"
    # Attempt to recognize category of assets
    elif local_ip != "" and remote_ip != "":
        if isInternalIP(local_ip) and isInternalIP(remote_ip):
            string += "Internal network assets\n"
        elif not isInternalIP(local_ip) and not isInternalIP(remote_ip):
            string += "WAN\n"
        else:
            string += "From \n"
            if isInternalIP(local_ip):
                string += "Internal network\n"
            else:
                string += "WAN\n"
            string += " to \n"
            if isInternalIP(remote_ip):
                string += "Internal endpoint\n"
            else:
                string += "WAN\n"
    return string

def returnAPIReport(apis_dict, key):
    if key in apis_dict:
        return apis_dict[key] + "\n"
    return ''

def writeProcessSubsection(ps_name, ps_cmd, ps_sha256, ps_signature, vt_report, ch_report):
    # # Processes subsection
    string = f"Command: `{ps_cmd}`\n"
    string += returnIfNonempty("SHA256", ps_sha256)
    string += returnIfNonempty("Signer", ps_signature)
    string += vt_report
    if ch_report != '':
        string += "\n" + ch_report
    return string

def defang(domain_string):
    # Separate out the domains from the string.
    match_object = re.match("^(.*?)([\w\-]+)\.([\w\-]+)\.([\w\-]+)((?:\.[\w\-]+){0,})([\w\-/]+\.[\w]+[\w\-?=/&]*)?(.*)$", domain_string)
    if match_object:
        return match_object.expand(r'\1`\2[.]\3[.]\4\5\6`\7')
    else:
        return  domain_string

# Takes a string of an IPv4 and puts [.] instead of . and quotes (`) around it.
def defangIP(ip):
    return f"`{ip.replace('.', '[.]')}`"
        
def writeFileSubsection(file_path, file_hash, vt_report):
    string = ''
    if file_path != '':
        string += "\nFile details:\n"
        string += returnIfNonempty("Path", file_path)
        string += returnIfNonempty("SHA256", file_hash)
        string += vt_report
    return string
    
def writeRegistrySubsection(registry_key, registry_data):
    string = ''
    if registry_data != '':
        string += "\nRegistry details:\n"
        string += returnIfNonempty("Key", registry_key)
        string += returnIfNonempty("Data", registry_data)
    return string

def writeNetworkSubsection(local_ip, local_port, remote_ip, remote_port, remote_host, app_id, apis_dict):
    string = ""
    if remote_ip != '':        
        string += f"\nNetwork connection: {local_ip}:{local_port} --> {remote_ip}:{remote_port}    ({app_id}"
        
        if remote_host != '':
            if not isInternalIP(remote_ip):
                remote_host = defang(remote_host)
            string += f", {remote_host})\n"
        else:
            string += ")\n"
        
    if ipIsRemote(local_ip):
        string += f"\nIP: {defangIP(local_ip)}\n"
        string += returnAPIReport(apis_dict, "local_ip_vt")
        string += returnAPIReport(apis_dict, "local_ip_ab")
    if ipIsRemote(remote_ip):
        string += f"\nIP: {defangIP(remote_ip)}\n"
        string += returnAPIReport(apis_dict, "remote_ip_vt")
        string += returnAPIReport(apis_dict, "remote_ip_ab")
        
    return string

def writeEmailSubsection(email_subject, email_sender, email_recipient):
    string = ''
    if email_subject != '':
        string += "\nEmail details:\n"
        string += returnIfNonempty("Subject", email_subject)
        string += returnIfNonempty("From", email_sender)
        string += returnIfNonempty("To", email_recipient)
    return string
    
def writeURLSubsection(remote_ip, url, user_agent, misc, dns_query):
    string = ""
    if url != "":
        if not isInternalIP(remote_ip):
            url = defang(url)
        string += returnIfNonempty("URL", url)
        string += returnIfNonempty("User agent", user_agent)
        string += returnIfNonempty("Misc", defang(misc))
        string += returnIfNonempty("DNS query", defang(dns_query))
    return string

def defangAlertName(alert_name):
    if not re.match(r'^Virus\/', alert_name):
        return defang(alert_name)
    return alert_name

def writeWhat(alert_dict, apis_dict):
    # What section
    string = "\n\nWhat:  \n-------------------------------------------  \n\n"
    string += returnIfNonempty("Alert name", defangAlertName(alert_dict['alert_name']))
    if not re.match(r"^\[ocd-xdr.*", alert_dict['alert_name']):
        string += returnIfNonempty("Description", defang(alert_dict['description']))
    
    if alert_dict['action'] != "":
        string += "\n"
    
    string += returnIfNonempty("Action", alert_dict['action'])
    string += returnIfNonempty("Alert source", alert_dict['alert_source'])
    if re.match(r'^Prevented', alert_dict['action']):
        string += returnIfNonempty("Module", alert_dict['module'])
    
    prev_cmds = []
    
    # Initiator process section
    if alert_dict['initiator_cmd'] != '':
        prev_cmds.append(alert_dict['initiator_cmd'])
        vt_report = returnAPIReport(apis_dict, "initiator_vt")
        ch_report = returnAPIReport(apis_dict, "initiator_ch")
        string += "\nInitiator details:\n"
        string += writeProcessSubsection(alert_dict['initiator_name'], alert_dict['initiator_cmd'], alert_dict['initiator_sha256'],\
            alert_dict['initiator_signature'], vt_report, ch_report)
    
    # CGO process section
    if alert_dict['cgo_cmd'] != '':
        vt_report = returnAPIReport(apis_dict, "cgo_vt")
        ch_report = returnAPIReport(apis_dict, "cgo_ch")
        string += "\nCausality group owner details:\n"
        if alert_dict['cgo_cmd'] not in prev_cmds:
            prev_cmds.append(alert_dict['cgo_cmd'])
            string += writeProcessSubsection(alert_dict['cgo_name'], alert_dict['cgo_cmd'], alert_dict['cgo_sha256'],\
                alert_dict['cgo_signature'], vt_report, ch_report)
        else:
            string += "Same as initiator.\n"
    
    # Target process section
    if alert_dict['target_process_cmd'] != '' and alert_dict['target_process_cmd'] not in prev_cmds:
        vt_report = returnAPIReport(apis_dict, "target_process_vt")
        ch_report = returnAPIReport(apis_dict, "target_process_ch")
        string += "\nTarget process details:\n"
        prev_cmds.append(alert_dict['target_process_cmd'])
        string += writeProcessSubsection(alert_dict['target_process_name'], alert_dict['target_process_cmd'], alert_dict['target_process_sha256'],\
            alert_dict['target_process_signature'], vt_report, ch_report)
    
    # # File subsection
    string += writeFileSubsection(alert_dict['file_path'], alert_dict['file_sha256'], returnAPIReport(apis_dict, "file_vt"))
    
    # Macro
    string += returnIfNonempty("Macro SHA256", alert_dict['file_macro_sha256'])

    # # Registry subsection
    string += writeRegistrySubsection(alert_dict['registry_key'], alert_dict['registry_data'])
    
    # # Network connection subsection
    string += writeNetworkSubsection(alert_dict['local_ip'], alert_dict['local_port'], alert_dict['remote_ip'], alert_dict['remote_port'], alert_dict['remote_host'], alert_dict['app_id'], apis_dict)
    
    # # Email subsection
    string += writeEmailSubsection(alert_dict['email_subject'], alert_dict['email_sender'], alert_dict['email_recipient'])
    
    # # URL subsection
    string += writeURLSubsection(alert_dict['remote_ip'], alert_dict['url'], alert_dict['user_agent'], alert_dict['misc'], alert_dict['dns_query'])
    
    
    return string

def writeReport(alert_dict, settings_dict, apis_dict):
    report = writeTitle(alert_dict['incident_id'])
    
    report += writeWho(alert_dict['username'], alert_dict['host'], alert_dict['host_ip'], alert_dict['host_os'], alert_dict['os_sub_type'])
    
    # Where section
    report += "\n\nWhere:  \n-------------------------------------------  \n\n"
    report += writeWhere(alert_dict['host'], alert_dict['local_ip'], alert_dict['remote_ip'], alert_dict['source_zone'], alert_dict['dest_zone'], alert_dict['domain'])
    
    # What Section
    report += writeWhat(alert_dict, apis_dict)
    
    # Why Section
    report += "\n\nWhy:  \n-------------------------------------------  \n\n"
    report += returnAPIReport(apis_dict, "why_ch")
    
    # When section
    report += "\n\nWhen:  \n-------------------------------------------  \n\n"
    timestamp = alert_dict['timestamp']
    if timestamp != '':
        report += timestamp + " UTC\n"
    
    # Footer section
    report += "\n\n\n_____________________________________________________________________________\n"
    report += f"# Other notes\n\nSearching\n```XQL\n{generateXQLQuery(timestamp)}```\n"
    
    return report
