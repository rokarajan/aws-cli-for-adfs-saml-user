#!/usr/bin/python
import sys
import boto.sts
import requests
import getpass
import configparser
import base64
import xml.etree.ElementTree as ET
import re
from bs4 import BeautifulSoup
from os.path import expanduser
from urllib.parse import urlparse

##########################################################################
region = 'ap-southeast-2'
outputformat = 'json'
awsconfigfile = '/.aws/credentials'
sslverification = True
idpentryurl = 'https://YOUR-ADFS-Server/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices'
print("Username:"),
username = input()
password = getpass.getpass()
print('')
session = requests.Session()
formresponse = session.get(idpentryurl, verify=sslverification)
idpauthformsubmiturl = formresponse.url
formsoup = BeautifulSoup(formresponse.text, "html.parser")
payload = {}

for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name','')
    value = inputtag.get('value','')
    if "user" in name.lower():
        payload[name] = username
    elif "email" in name.lower():
        payload[name] = username
    elif "pass" in name.lower():
        payload[name] = password
    else:
        payload[name] = value
for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
    action = inputtag.get('action')
    loginid = inputtag.get('id')
    if (action and loginid == "loginForm"):
        parsedurl = urlparse(idpentryurl)
        idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action
response = session.post(
    idpauthformsubmiturl, data=payload, verify=sslverification)

username = '##############################################'
password = '##############################################'
del username
del password

soup = BeautifulSoup(response.text, "html.parser")
assertion = ''

for inputtag in soup.find_all('input'):
    if(inputtag.get('name') == 'SAMLResponse'):
        assertion = inputtag.get('value')

if (assertion == ''):
    print ('Response did not contain a valid SAML assertion')
    sys.exit(0)
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)


for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

print("")
if len(awsroles) > 1:
    i = 0
    print("Please choose the role you would like to assume:")
    for awsrole in awsroles:
        print('[', i, ']: ', awsrole.split(',')[0])
        i += 1
    print("Selection: "),
    selectedroleindex = input()

    if int(selectedroleindex) > (len(awsroles) - 1):
        print('You selected an invalid role index, please try again')
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
else:
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]

conn = boto.sts.connect_to_region(region)
token = conn.assume_role_with_saml(role_arn, principal_arn, assertion)

home = expanduser("~")
filename = home + awsconfigfile

config = configparser.RawConfigParser()
config.read(filename)

if not config.has_section('saml'):
    config.add_section('saml')

config.set('saml', 'output', outputformat)
config.set('saml', 'region', region)
config.set('saml', 'aws_access_key_id', token.credentials.access_key)
config.set('saml', 'aws_secret_access_key', token.credentials.secret_key)
config.set('saml', 'aws_session_token', token.credentials.session_token)

with open(filename, 'w+') as configfile:
    config.write(configfile)

print('\n\n----------------------------------------------------------------')
print('Your new access key pair has been stored in the AWS configuration file {0} under the saml profile.'.format(filename))
print('Note that it will expire at {0}.'.format(token.credentials.expiration))
print('After this time, you may safely rerun this script to refresh your access key pair.')
print('To use this credential, call the AWS CLI with the --profile option')
print('----------------------------------------------------------------\n\n')