import os
import sys
import argparse

from aux_functions import loadJsonFile
from credential_protection import loadCredentials, encryptCredentialsToFile
from report_generation import generateReport


# Implements the logic of the command-line arguments.
def advancedUsage(parser, settings_dict):

    cli_input = parser.parse_args()


    # First we encrypt and save credentials, if that was the point of the invocation
    if cli_input.encrypt:
        credentials = loadCredentials(folder_name = settings_dict['credentials-folder'],\
            output_fn = settings_dict['encrypted-credentials-name'])
        encryptCredentialsToFile(credentials, output_fn = settings_dict['encrypted-credentials-name'])
        return
    
    return



# Parse command-line arguments
#
# What we want here is to have the behavior.
# If no command line arguments is given, the script reads the settings.conf file (which is a json formatted file),
# this specifies where to look for an output-file path. It then tried to read this file and generate a report
# accordingly
# --encrypt
#   If this is specified, the script tried to read the cleartext credentials in the credentials folder (whose path 
#   is specified in the settings.conf file. It then encrypts them using a password according to the
#   credentials_protection module and stores the encrypted credentials in a file api_credentials.json
def main(argv):

    # Load settings from configuration file.
    settings_file = "settings.conf"
    settings_dict = loadJsonFile(settings_file)
    
    # If no argument is given
    if len(argv) <= 0:
        credentials = loadCredentials(folder_name = settings_dict['credentials-folder'],\
            output_fn = settings_dict['encrypted-credentials-name'])
        report, output_path = generateReport(settings_dict, credentials)
        #print(report)
        
        
        
        # Save file
        with open(output_path, "w", encoding="utf8") as file:
            print(report, file=file, end='')
            
        cmd = settings_dict['text-program-path'] + " \"" + output_path + "\""
        print(cmd)
        os.system(cmd)
    else:
        
        # If an argument is given, we parse the arguments with argparse

        parser = argparse.ArgumentParser(prog='alert_transform.py',\
            description='Takes the output from an alert in Cortex XDR and generates a report according to the\
            5W format. In this report we also incorporate lookups from external data sources such as Virustotal\
            AbusedIPDB and ChatGPT.')
        
        parser.add_argument('-e', '--encrypt', action='store_true', help='Attempts to encrypt credentials stored in cleartext in the credentials folder with a password. Then saves the encrypted credentials to a file `api_credentials.json` located in the script folder.')

        advancedUsage(parser, settings_dict)
        
    return

if __name__ == "__main__":
   main(sys.argv[1:])
   
