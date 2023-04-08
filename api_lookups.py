# Places where we have found api lookups:
"""
if alert_dict['initiator_cmd'] != '':
        ...
        if not isTrustedProcess(alert_dict['initiator_name'], alert_dict['initiator_signature']):
            printVTHash(file_hash, vt_api, ostream=ostream)
        if not hasCommonName(alert_dict['initiator_name']):
            print("", file=ostream)
            printChatGPTProcess(alert_dict['initiator_name'], ch_api, ostream=ostream)
            
if alert_dict['cgo_cmd'] != '':
    if alert_dict['cgo_cmd'] != alert_dict['initiator_cmd']:
        ... same as above

if alert_dict['target_process_cmd'] != '':
    ...
    if not isTrustedProcess(alert_dict['target_process_name'], alert_dict['target_process_signature']):
            printVTHash(file_hash, vt_api, ostream=ostream)
        if not alert_dict['target_process_name'] in [alert_dict['initiator_name'], alert_dict['cgo_name']] and not hasCommonName(alert_dict['target_process_name']) :
            print("", file=ostream)
            printChatGPTProcess(alert_dict['target_process_name'], ch_api, ostream=ostream)

if alert_dict['file_path'] != '':
    ...
    printVTHash(file_hash, vt_api, ostream=ostream)

if alert_dict['remote_ip'] != '':
    printIPAnalysis(alert_dict['local_ip'], alert_dict['remote_ip'], vt_api = vt_api, ab_api = ab_api, ostream=ostream)
    
# Why section
printChatGPTAnswer(alert_dict, ch_api, ostream=ostream)

"""

import asyncio
import aiohttp
from pprint import pprint

from aux_functions import isTrustedProcess

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

async def virustotalHashReport(file_hash, vt_api):
    return "lol"

async def asyncTestFunc():
    return "trall"

# Make all necessary API lookups in an asynchronous manner, then synchronize threads
# and return information in a dictionary for each API-lookup.
async def asyncAPILookups(alert_dict, settings_dict, credentials):
    
    # Separate credentials into variables
    vt_api, ab_api, ch_api = separateCredentials(credentials)
    
    # Setup connection pool
    async with aiohttp.ClientSession() as session:
        tasks = []
        
        # Determine if API calls are necessary, and if they are: add them to the tasks
        if alert_dict['initiator_cmd'] != '' and not isTrustedProcess(alert_dict['initiator_name'], alert_dict['initiator_signature'], settings_dict):
            file_hash = alert_dict['initiator_sha256']
            task = asyncio.create_task(virustotalHashReport(file_hash, vt_api))
            tasks.append(task)
        
        task = asyncio.create_task(asyncTestFunc())
        tasks.append(task)
        
        results = await asyncio.gather(*tasks)
    
    return results

# Auxhillary function to run and return the asynchronous tasks
def makeAsyncAPILookups(alert_dict, settings_dict, credentials):
    results = asyncio.run(asyncAPILookups(alert_dict, settings_dict, credentials))
    
    pprint(results) # Debug
    exit(-1) # Debug
    
    return apis_dict