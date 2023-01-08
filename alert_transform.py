import sys
import os

from alert_transform_funcs import printReport, eprint, readFile, generateAlertDictionary

def printHelp():
    eprint("py check_ips.py <filename>\n")
    eprint("Here <filename> is the path to the file where you pasted the cortex alert output after selecting \"Copy entire row\".")

# Parse command-line arguments
def main(argv):
    
    try:
        # Treat everything after the python script as a path to the input file.
        file_path = os.path.normpath(''.join(argv))
    except:
        printHelp()
        eprint(argv)
        sys.exit(2)
    
    alert_string = readFile(file_path)
    alert_dict = generateAlertDictionary(alert_string)
    
    output_filename = alert_dict['alert_id'] + "_output.md"
    if os.path.exists(output_filename):
        print("File already exists")
        
    with open(output_filename, "w") as file:
        printReport(alert_dict, ostream=file)
    
    cmd = "\"C:\\Program Files\\Notepad++\\notepad++.exe\" " + output_filename
    os.system(cmd)
    
    return

if __name__ == "__main__":
   main(sys.argv[1:])
   
