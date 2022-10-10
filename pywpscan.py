print('''
-------------------------------------------------------------
           __          _______                     
           \ \        / /  __ \                    
  _ __  _   \ \  /\  / /| |__) |__  ___ __ _ _ __  
 | '_ \| | | \ \/  \/ / |  ___/ __|/ __/ _` | '_ \ 
 | |_) | |_| |\  /\  /  | |   \__ \ (_| (_| | | | |
 | .__/ \__, | \/  \/   |_|   |___/\___\__,_|_| |_|
 | |     __/ |                                     
 |_|    |___/                                  v0.1.0

 pyWPScan - Wpscan json file formatter
 by Baris Caglar
 -------------------------------------------------------------
 ''')
# import required libraries
import json
import os
import sys
import argparse

# Create the parser
my_parser = argparse.ArgumentParser(description='This API takes JSON file name as input, filters them, and saves the results to a new json file.')
my_parser.add_argument('--input', '-i', metavar='input', action='store', type=str, required=True, help='To load, type the name of the json file.')
my_parser.add_argument('--output', '-o', action='store', type=str, required=True, help='To save the output json file, type the name.')
args = my_parser.parse_args()

# check if a given json file exists
if not os.path.isfile(args.input):
    print('The input path specified does not exist')
    sys.exit()

# load json file and filter the data
def wp_analysis():
    #create empty dictionary
    collected_replies = {}
    
    # load json data
    with open(args.input, "r") as f:
        scan_data = json.load(f)

    
    # Target Site
    if len(scan_data['target_url']) != 0:
        collected_replies = get_data('target_url', scan_data['target_url'], collected_replies)
    if len(scan_data['target_ip']) != 0:
        collected_replies = get_data('target_ip', scan_data['target_ip'], collected_replies)
    
    # Wordpress
    if len(scan_data['version'].get("number")) != 0:
        collected_replies = get_data('wp_version', scan_data['version'].get("number"), collected_replies)
    if len(scan_data['version'].get("status")) != 0:
        collected_replies = get_data('wp_status', scan_data['version'].get("status"), collected_replies)
    if len(scan_data['version']['vulnerabilities']) != 0:
        collected_replies = get_data('wp_vulnerabilities',scan_data['version']['vulnerabilities'], collected_replies)
    
    # Wordpress Theme
    if len(scan_data['main_theme'].get("style_name")) != 0:
        collected_replies = get_data('theme_name', scan_data['main_theme'].get("style_name"), collected_replies)
    if len(scan_data['main_theme'].get('version').get('number')) != 0:
        collected_replies = get_data('theme_version', scan_data['main_theme'].get('version').get('number'), collected_replies)
    if len(scan_data['main_theme']['vulnerabilities']) != 0:
        collected_replies = get_data('theme_vulnerability', scan_data['main_theme']['vulnerabilities'], collected_replies)
    if len(scan_data['main_theme'].get('parents')[0].get('vulnerabilities')) != 0:
        collected_replies = get_data('parents_theme_vulnerability', scan_data['main_theme'].get('parents')[0].get('vulnerabilities'), collected_replies)
    # Server Info
    if len(scan_data['interesting_findings'][0]['interesting_entries']) != 0:
        collected_replies = get_data('server_infos', scan_data['interesting_findings'][0]['interesting_entries'], collected_replies)
    
    # Plugins
    if len(scan_data['plugins']) != 0:
        collected_replies = wp_vul_plugins(scan_data['plugins'], collected_replies)
    
    # check if dictionary not empty
    if collected_replies:
        return collected_replies
    else:
        return "no data found"

# update the dictionary with new findings
def get_data(dictkey, dictvalue, collected_replies):
    if dictvalue:
        collected_replies.update({dictkey: dictvalue})
        return collected_replies
    else:
        return False


# check vulnerable plugins
def wp_vul_plugins(get_data, collected_replies):
    if get_data:
        vul_plugins = []
        plugins_values = []
        for plugin in get_data.keys():
            plugins_values.append(plugin)
        for value in plugins_values:
            if get_data[value].get('vulnerabilities') and get_data[value].get('confidence') > 50:
                vul_plugins.append(f'{value}{get_data[value].get("vulnerabilities")}')
                collected_replies.update({'plugins': vul_plugins})
        return collected_replies
    else:
        return False

# save as a new json file
def save_to_json():
    with open(args.output, 'w') as f:
        json.dump(wp_analysis(), f, indent=4)
        print(f'The "{args.output}" saved to the current directory')

# call it save function
save_to_json()
