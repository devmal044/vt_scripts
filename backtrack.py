import datetime
import time
from datetime import timedelta
import requests
import json
import csv
from pathlib import Path

tag = input("Malware Tag? ex. Emotet, petya : ")
fs = input("Start Date? yyyy-mm-dd: ")
fst = input("Start Time: HH:MM:SS: ")
ls = input("End Date? yyyy-mm-dd: ")
lst = input("End Time: HH:MM:SS: ")

hash_list = []

year, month, day = map(int, fs.split('-'))
hour, minute, second = map(int, fst.split(':'))
st = datetime.datetime(year, month, day, hour, minute, second)
year, month, day = map(int, ls.split('-'))
hour, minute, second = map(int, lst.split(':'))
et = datetime.datetime(year, month, day, hour, minute, second)

headers = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent" : "gzip,  My Python requests library example client or username"
}
params = {'apikey': '<INSERT API KEY>', 'query': ''}

while st <= et:
    qts = str(st).replace(" ", "T")
    qte = st + timedelta(minutes=59, seconds=59)
    qte = str(qte).replace(" ", "T")
    params["query"] = 'bitdefender:' + tag + ' OR clamav:' + tag + ' OR crowdstrike:' + tag + ' OR cylance:' + tag + ' OR endgame:' + tag + ' OR eset_nod32:' + tag + ' OR f_secure:' + tag + ' OR fortinet:' + tag + ' OR kaspersky:' + tag + ' OR malwarebytes:' + tag + ' OR mcafee:' + tag + ' OR mcafee_gw_edition:' + tag + ' OR microsoft:' + tag + ' OR nod32:' + tag + ' OR paloalto:' + tag + ' OR sophos:' + tag + ' OR symantec:' + tag + ' OR symantecmobileinsight:' + tag + ' OR trendmicro:' + tag + ' OR trendmicro_housecall:' + tag + ' fs:' + qts + '+' + ' AND ls:' + qte + '-' + ' positives:11+'

    response = requests.post('https://www.virustotal.com/vtapi/v2/file/search', data=params, headers=headers)
    response_json = response.json()
    
    if 1 != response_json['response_code']:
     #print(params)
     st = st + timedelta(hours=1)
     #print("No hashes or you mustve entered in something wrong. Maybe the bad guys are taking a break, try again!!!!!")
     continue
    elif 1 == response_json['response_code']:

     for every_hash in response_json['hashes']:
      hash_list.append(every_hash)
 
     if 'offset' in response_json and len(response_json['hashes']) == 300:
      offset_v = response_json['offset']
      params.update({'offset':offset_v})
      count_h = len(response_json['hashes'])
      while count_h == 300:
       response = requests.post('https://www.virustotal.com/vtapi/v2/file/search', data=params, headers=headers)
       response_json = response.json()
       if 'offset' in response_json:
        if offset_v != response_json['offset']:
         offset_v = response_json['offset']
       else: 
        del params['offset']
       for every_hash in response_json['hashes']:
        hash_list.append(every_hash)
       count_h = len(response_json['hashes'])

     #trends = [tag, st.strftime("%Y-%m-%d %H:%M:%S"), str(count)]
     trends_f = Path("hashes.csv")

     if trends_f.is_file():
      with open('hashes.csv', 'a', newline='') as csv_file:	
       trendwriter = csv.writer(csv_file)
       for hash in hash_list:
        trends = [tag, st.strftime("%Y-%m-%d %H:%M:%S"), hash]
        trendwriter.writerow(trends)
     else:
      with open('hashes.csv', 'w', newline='') as csv_file:	
       trendwriter = csv.writer(csv_file)
       trendwriter.writerow(['tag', 'date', 'hash'])
       for hash in hash_list:
        trends = [tag, st.strftime("%Y-%m-%d %H:%M:%S"), hash]
        trendwriter.writerow(trends)
     st = st + timedelta(hours=1)
     time.sleep(1)
