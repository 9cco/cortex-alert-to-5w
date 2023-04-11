Alert Transform
======================================================

![Visitors](https://visitor-badge.glitch.me/badge?page_id=9cco.cortex-alert-to-5w)
[![Say Thanks!](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://saythanks.io/to/9cco)

The script converts a row of a Cortex alert into a 5W compliant report. It uses "machine-learning" (*[chat-GPT](https://platform.openai.com/docs/api-reference)*) to enrich the results as well as data
from *[Virustotal](https://developers.virustotal.com/reference/overview)* and *[AbusedIPDB](https://www.abuseipdb.com/api.html)*. It implements automatic and manual searching for sensitive information and protects API credentials using *AES-256* symmetric
encryption based on a key derived using a password and the *Argon2* memory-hard PBKDF. API requests are parallelized using the *asyncio* and *aiohttp* libraries. Also, everything is held together using a lot of *regex* ᵉʰᵉʰᵉ(\*\/∇＼⭒) 

## Installation

Download the repository either by clicking on **Code** in the top right, then click **Download ZIP** and finally extract the zip to a folder of your choice.
Alternatively, if you have git installed, you can run the command `git clone https://github.com/9cco/cortex-alert-to-5w.git` which will download the
repository automatically including the change-history.

### Installing required python modules

First of all you will need to have **python3** installed on your system as well as **pip**. Once you have this installed, install the required
python packages by running
```
pip install -r requirements.txt
```
in the folder with the script. In windows, unless you have an alias for `pip`, you will need to do
```
python -m pip install -r requirements.txt
```

### Configuring settings

Before using the script, you will have to configure a settings-file. An example file is included with the same `settings.example`. Rename this file to
`settings.conf`. Then, in the file, for each field that has a backet as a value like `<some description of the field>`, insert information of your choice. 
The `settings.conf` file will be interpreted as a json file, so make sure to use json-formatting when inserting the information. For information on how
to format a json file [see here](https://www.w3schools.com/js/js_json_syntax.asp).

There are two keys that it is required that you fill out: 
- `"cortex-output-file-path"`: For this key, insert the path to the file where you will be pasting the output you get from copying the row you find in Cortex
	for the alert. Remember to use double back-slashes within the string. So if you would like to store Cortex data in the file `output.txt` in the folder
	`C:\Users\<user>\Documents`, you would need to enter
	
		"cortex-output-file-path" : "C:\\Users\\<user>\\Documents\\output.txt"
	
- `"output-folder"`: This is the path to the folder where you want the resulting report-files to be stored.

Another key you might want to configure if the `"info-searches"` key. The value of this key is a list of search strings which will be used to automatically search
for sensitive information in the Cortex output before sending it off to third party services like Chat GPT.

### Enabling API lookups

Specifically we have functionality for lookup on AbusedIPDB, Virustotal and chatGPT. First you will need to gather the API-key for each of these services.
You can find information about how do obtain these on these services respective websites, but they will all come in the form of a string of text.
Create a folder named `credentials` in the same folder as the script. Then copy the respective API-keys into the files:
- `abusedipdb_api_key.txt`,
- `chatgpt_api_key.txt`,
- `virustotal_api_key.txt`.

This is all you need to do to use API-lookups, however if you don't want to leave these cleartext credentials on your harddrive, you can encrypt them
with a password by running
```
python3 alert_transform.py --encrypt
```

### Accellerating workflow

In order to accellerate your workflow when using this script, it is highly recommended to make a shortkcut key-combination in order to execute it. In windows, do this by going to the file `alert_transform.py`, then right click and select *Create Shortcut*. Move the shortcut to where-ever you like, e.g., the Desktop. Right-click the shortcut, select *Properties* and enter your desired key in the field *Shortcut key:*. The shortcut key will then be **CTRL** + **ALT** + **\<your key\>**.

For easier execution of the script in PowerShell, it is also recommended to make an alias for it in your PowerShell Profile script. This script is normally located in `C:\Users\<username>\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`. Open the script in your favourite text editor, e.g. if using notepad++, you can execute the command
```
start notepad++ $profile
```
Then, paste in the following code,
```
function gen {
	$script_path = "<path to python script>"
	py $script_path $args
}
```
and change the path to the path to the script `alert_transform.py` where you placed the script files. You can also change the function name `gen` to be anything you like, e.g., `report`. Now, when you open a new powershell prompt, you can execute the script by typing the command `gen`.

## Use

Once everything is set up, go to an alert in Cortex XDR. Make sure to use the default layout of fields by clicking the "three dots" and selecting *default layout*.
Also make sure that all fields are included by checking the *select all* checkbox in the same menu. Now, right click somewhere in the alert row and select
**copy entire row**. Go to the file you previously setup for dumping cortex output, open the file in your faviourite text-edit and paste it into the file (**Ctrl**+**v**). Now, if you have set up the accellerated workflow, as described above, all you need to do is to push the shortcut-key combination. If not, open a powershell prompt, navigate to the folder with the script and run
```
python3 alert_transform.py
```
This wil generate the report in the folder you previously configured and open it in `notepad++` (if you are using another text-editor, you can configure the report to be opened in this by editing the `"text-program-path"` key in the `settings.conf` file).