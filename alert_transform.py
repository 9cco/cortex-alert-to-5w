import sys
import os
import json

from alert_transform_funcs import printReport, eprint, readFile, generateAlertDictionary, getDay

def printHelp():
    eprint("py check_ips.py <filename>\n")
    eprint("Here <filename> is the path to the file where you pasted the cortex alert output after selecting \"Copy entire row\".")
    
def getSettings(filename):
    # Get current script folder path
    script_folder = os.path.normpath(os.path.dirname(os.path.realpath(__file__)))
    conf_path = script_folder + "/" + filename
    
    if os.path.exists(conf_path):
        with open(conf_path, "r") as f:
            conf_dict = json.load(f)
        return conf_dict
    
    printHelp()
    eprint(f"Could not find settings file at: \n{conf_path}")
    exit(-2)

# Returns a string with the API key if it can find it in the file credentials/virustotal_api_key.txt
# relative to the script path.
def getAPIKey(filename):
    dir_path = os.path.normpath(os.path.dirname(os.path.realpath(__file__)))
    path = dir_path + "/credentials/" + filename
    if os.path.exists(path):
        with open(path, "r") as file:
            api_key = file.read()
        return api_key
    else:
        eprint("Could not find api key at: " + path)
        exit(-2) 

# Parse command-line arguments
def main(argv):
    
    settings_file = "conf.json"
    vt_api_file = "virustotal_api_key.txt"
    
    try:
        # Treat everything after the python script as a path to the input file.
        file_path = os.path.normpath(''.join(argv))
    except:
        printHelp()
        eprint(argv)
        sys.exit(2)
    
    try:
        vt_api = getAPIKey(vt_api_file)
    except:
        eprint("Failed to get VT API-key")
        sys.exit(3)
    
    conf_dict = getSettings(settings_file)
    
    alert_string = readFile(file_path)
    alert_dict = generateAlertDictionary(alert_string)
    
    output_filename = getDay(alert_dict['timestamp']) + "_(customer_id)_" + alert_dict['incident_id'] + ".md"
    if os.path.exists(output_filename):
        eprint("Overwriting existing file.")
        
    with open(output_filename, "w") as file:
        printReport(alert_dict, vt_api = vt_api, conf_dict=conf_dict, ostream=file)
    
    cmd = "\"C:\\Program Files\\Notepad++\\notepad++.exe\" " + output_filename
    os.system(cmd)
    
    return

if __name__ == "__main__":
   main(sys.argv[1:])
   
