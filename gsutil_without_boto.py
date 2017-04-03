# -*- coding: utf-8 -*-
"""
Created on Tue Mar 28 18:58:28 2017

@author: dell
"""

import pprint
from oauth2client.service_account import ServiceAccountCredentials
import httplib2
from googleapiclient.discovery import build

from google.cloud import storage
from oauth2client.file import Storage
from oauth2client import client

from httplib2 import Http

from oauth2client.client import OAuth2WebServerFlow


# --------------- Authorize using service account ------------------------------
client_email = 'newbucket@datalab1-159607.iam.gserviceaccount.com'
private_key_password = 'notasecret'
scopes = ['https://www.googleapis.com/auth/cloud-platform']

credentials = ServiceAccountCredentials.from_p12_keyfile(client_email, 'C:\Users\dell\Downloads\keyfile.p12', private_key_password, scopes)
http_auth = credentials.authorize(Http())

service = build('storage', 'v1', http_auth)
request = service.buckets().get(bucket='lavabucket1')


#request = service.buckets().list(project="datalab1-159607")
#request= service.objects.list()
    


#flow = OAuth2WebServerFlow(client_id, client_secret, scope)





from oauth2client import tools
import json
try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None
    
  
#--------------------- Authorize using OAuth2 credentials --------------------------------  
CLIENT_SECRET_FILE = 'C:\Users\dell\Downloads\client_secret.json'
SCOPES='https://www.googleapis.com/auth/cloud-platform'
APPLICATION_NAME = 'Lava Client Other'

credential_path = 'C:\Users\dell\Downloads\start.json'

store = Storage(credential_path)
credentials = store.get()

if not credentials or credentials.invalid:
    flow = client.flow_from_clientsecrets(CLIENT_SECRET_FILE, SCOPES)
    flow.user_agent = APPLICATION_NAME
    if flags:
        credentials = tools.run_flow(flow, store, flags)
    else: # Needed only for compatibility with Python 2.6
        credentials = tools.run(flow, store)
    print('Storing credentials to ' + credential_path)


http = credentials.authorize(httplib2.Http())
service = build('storage', 'v1', http)
request = service.buckets().get(bucket='lavabucket1')

# Diagnostic

pprint.pprint(request.headers)
pprint.pprint(request.to_json())

# Do it!

response = request.execute()
pprint.pprint(response)






request = service.objects().list(bucket='lavabucket1')


#request = service.objects().get(bucket= 'lavabucket1', object='hello.txt')


# Creates the new bucket
storage_client = storage.Client()
# The name for the new bucket
bucket_name = 'new-bucket-lava1'
bucket = storage_client.create_bucket(bucket_name)




# Instantiates a client



# Diagnostic

pprint.pprint(request.headers)
pprint.pprint(request.to_json())

# Do it!

response = request.execute()
pprint.pprint(response)