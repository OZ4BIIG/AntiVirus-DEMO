# -*- coding: utf-8 -*-
import requests
import os
import time

API_KEY = "570d5818b407125d8854efbe73b7a9abf1fb88352ec5d8510751cbe645e9b9e8"
url = "https://www.virustotal.com/api/v3/files"

headers = {
    "accept": "application/json",
    "x-apikey": API_KEY
}

def scan_file(file_path):
    with open(file_path, "rb") as file:
        files = {"file": (os.path.basename(file_path), file)}
        response = requests.post(url, files=files, headers=headers)
    
    result = response.json()
    
    if 'data' in result:
        analysis_url = result['data']['links']['self']
        time.sleep(15)
        
        analysis_response = requests.get(analysis_url, headers=headers)
        analysis_data = analysis_response.json()
        
        if 'data' in analysis_data and 'attributes' in analysis_data['data']:
            stats = analysis_data['data']['attributes'].get('stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            
            return "Detections: {}/{}".format(malicious, total)
    
    return "Error scanning file"

def scan_directory(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            print("File: {}".format(os.path.basename(file_path)))
            print("Result: {}".format(scan_file(file_path)))
            print()

scan_directory("../test_files")