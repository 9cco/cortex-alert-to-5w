import os
import re
from pprint import pprint

from aux_functions import eprint
from api_lookups import makeAsyncAPILookups
from report_sections import writeReport

# Read the input file specified by the path in the settings.
def readInputFile(settings_dict):
    file_path = settings_dict['cortex-output-file-path']
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            alert_string = file.read()
        return alert_string
    else:
        raise Exception("Could not find the file at:" + file_path)

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


def getDay(timestamp):
    match_object = re.search("([0-9]{1,2})[^0-9]{2}", timestamp)
    return match_object.expand(r"\g<1>")

# Generates a string containing the entire report.
def generateReport(settings_dict, credentials):
    
    # Read input file.
    alert_string = readInputFile(settings_dict)
    # Format input file into a dictionary.
    alert_dict = generateAlertDictionary(alert_string)
    
    # Based on the available information in the alert, make necessary lookups. These will
    # be used later when generating the report.
    apis_dict = makeAsyncAPILookups(alert_dict, settings_dict, credentials)
    
    report = writeReport(alert_dict, settings_dict, apis_dict)
    
    # Generate output filename and output path and check if it already exists
    output_filename = getDay(alert_dict['timestamp']) + "_(customer_id)_" + alert_dict['incident_id'] + ".md"
    output_path = os.path.join(settings_dict['output-folder'], output_filename)
    if os.path.exists(output_path):
        choice = input(f"File {output_filename} already exists. Overwrite? (y/n): ")
        if not 'y' in choice.lower():
            exit(-1)
    
    return report, output_path