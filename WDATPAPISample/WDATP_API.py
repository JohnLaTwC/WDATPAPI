# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------

# Author: @JohnLaTwC

## https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-atp/run-advanced-query-api

import json
import urllib.request
import urllib.parse
import pandas as pd
import re
from IPython.core.magic import (register_line_magic, register_cell_magic,
                                register_line_cell_magic)

SPLIT_DELIMS = '[\[\] ;\n\t|,xX"\']'
@register_line_cell_magic
def hash(line, cell=None):
    if cell is None:
        return line
    else:    
        results = []
        for f in re.split(SPLIT_DELIMS,cell):
            p = re.compile('^[a-f0-9]{32}$'
                           '|^[a-f0-9]{40}$'
                           '|^[a-f0-9]{64}$'
                           ,re.IGNORECASE)
            if p.search(f) is not None:
                if not f in results:
                    results.append(f)
        
        return results           

# We delete these to avoid name conflicts for automagic to work
del hash 

@register_line_cell_magic
def vthash(line, cell=None):
    if cell is None:
        return wdatp_api.vtresults([line])
    else:    
        results = []
        for f in re.split(SPLIT_DELIMS,cell):
            p = re.compile('^[a-f0-9]{32}$'
                           '|^[a-f0-9]{40}$'
                           '|^[a-f0-9]{64}$'
                           ,re.IGNORECASE)
            if p.search(f) is not None:
                if not f in results:
                    results.append(f)
        
        if len(results) == 0:
            return
        return wdatp_api.vtresults(results)
           

# We delete these to avoid name conflicts for automagic to work
del vthash 

@register_line_cell_magic
def wdatp_file(line, cell=None):
    if cell is None:
        return wdatp_api.files(filehash=line)
    else:    
        results = []
        for f in re.split(SPLIT_DELIMS,cell):
            p = re.compile('^[a-f0-9]{40}$',re.IGNORECASE)
            if p.search(f) is not None:
                if not f in results:
                    results.append(f)
        
        if len(results) == 0:
            return
        dfs = []
        for filehash in results:
            dfs.append(wdatp_api.files(filehash=filehash))
        import pandas as pd
        return pd.concat(dfs)
            
# Delete these to avoid name conflicts for automagic to work
del wdatp_file

@register_line_cell_magic
def wdatp_machine(line, cell=None):
    if cell is None:
        if re.match('^[a-f0-9]{40}$', line):
            return wdatp_api.machines(machineid=line)
        else:
            return wdatp_api.machines(filterstr="$filter=ComputerDnsName eq '%s'" % line)
    else:    
        results = []
        for f in re.split(SPLIT_DELIMS,cell):
            p = re.compile('^[a-f0-9]{40}$',re.IGNORECASE)
            if p.search(f) is not None:
                if not f in results:
                    results.append(f)
        
        dfs = []

        # if we did not get any machine Ids, treat them as ComputerDnsNames
        if len(results) == 0:
            results = cell.split('\n')
            for hostname in results:
                dfs.append(wdatp_api.machines(filterstr="$filter=ComputerDnsName eq '%s'" % hostname))
        else:
            for machine_id in results:
                dfs.append(wdatp_api.machines(machineid=machine_id))
        import pandas as pd
        return pd.concat(dfs)
            
# Delete these to avoid name conflicts for automagic to work
del wdatp_machine 

@register_line_cell_magic
def wdatp_alert(line, cell=None):
    if cell is None:
        return wdatp_api.alerts(alertid=line)
    else:    
        results = []
        for f in re.split(SPLIT_DELIMS,cell):
            p = re.compile('^[\d]{18}_\-*[\d]{5,16}$',re.IGNORECASE)
            if p.search(f) is not None:
                if not f in results:
                    results.append(f)
        if len(results) == 0:
            return
        dfs = []
        for alert_id in results:
            dfs.append(wdatp_api.alerts(alertid=alert_id))
        import pandas as pd
        return pd.concat(dfs)

# Delete these to avoid name conflicts for automagic to work
del wdatp_alert 

@register_line_cell_magic
def wdatp_ip(line, cell=None):
    if cell is None:
        return wdatp_api.ips(ip=line)
    else:    
        results = []
        for f in re.split(SPLIT_DELIMS,cell):
            p = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
            if p.search(f) is not None:
                if not f in results:
                    results.append(f)
        if len(results) == 0:
            return
        dfs = []
        for ip in results:
            dfs.append(wdatp_api.ips(ip=ip))
        import pandas as pd
        return pd.concat(dfs)
            
# Delete these to avoid name conflicts for automagic to work
del wdatp_ip 
        
@register_line_cell_magic
def wdatp_action(line, cell=None):
    if cell is None:
        return wdatp_api.ips(ip=line)
    else:    
        results = []
        for f in re.split(SPLIT_DELIMS,cell):
            p = re.compile('^[a-f0-9]{8}'
                       '-[a-f0-9]{4}'
                       '-[a-f0-9]{4}'
                       '-[a-f0-9]{4}'
                       '-[a-f0-9]{12}$'
                       ,re.IGNORECASE)
            if p.search(f) is not None:
                if not f in results:
                    results.append(f)
        if len(results) == 0:
            return
        dfs = []
        for action in results:
            dfs.append(wdatp_api.machine_actions(actionid = action))
        import pandas as pd
        return pd.concat(dfs)
            
# Delete these to avoid name conflicts for automagic to work
del wdatp_action
    
class WDATP:
    def __init__(self, tenantId, appId, appSecret, fUsePandas=True, api_root="https://api.securitycenter.windows.com", vt_api_key=None):
        url = "https://login.windows.net/%s/oauth2/token" % (tenantId)

        self.fDebug = False
        resourceAppIdUri = 'https://api.securitycenter.windows.com'

        body = {
            'resource' : resourceAppIdUri,
            'client_id' : appId,
            'client_secret' : appSecret,
            'grant_type' : 'client_credentials'
        }

        ## authenticate and obtain AAD Token for future calls
        data = urllib.parse.urlencode(body).encode("utf-8")
        req = urllib.request.Request(url, data)
        response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read())
        self.aadToken = jsonResponse["access_token"]
        self.headers = { 
            'Content-Type' : 'application/json',
            'Accept' : 'application/json',
            'Authorization' : "Bearer " + self.aadToken
        }
        self.fUsePandas = fUsePandas # use pandas DataFrame for collections of objects, else return a list
        self.api_root = api_root
        self.vt_api_key = vt_api_key
    
    def set_output_type(self, fUsePandas=True):
        self.fUsePandas = fUsePandas    

    def set_debug_output(self, fDebug=True):
        self.fDebug = fDebug    
        
    def __validate_arguments(self,args, valid_params):
        if len(args) == 0:
            raise ValueError ('argument must be one of %s' % str(list(valid_params.keys())))
        elif len(args) > 1:
            raise ValueError ('only one id can be used at a time')
        else:
            selector = next(iter(args))
            selector_value= next(iter(args.values()))
            if selector not in list(valid_params.keys()):
                raise ValueError ('argument must be one of %s' % str(list(valid_params.keys())))
        return (selector, selector_value)

    def __make_request(self,url, params=None):
 
        if self.fDebug:
            print(url)
        req = urllib.request.Request(url, headers=self.headers)
        try:
            response = urllib.request.urlopen(req)
        except urllib.error.HTTPError as e:
            raise e
                
        jsonResponse = json.loads(response.read())
        if type(jsonResponse) == int:
            if self.fUsePandas:
                return pd.DataFrame([jsonResponse])
            else:
                return jsonResponse
        if 'value' in jsonResponse:
            res = jsonResponse["value"]
        else:
            res = jsonResponse     
        if self.fUsePandas:
            return pd.io.json.json_normalize(res)
        return res

    def __prepare_param_dict_from_filter_str(self, filterstr):
        get_params = {}
        for filter_param in re.split("[\?\&]+", filterstr):
            if len(filter_param)> 0:
                attr = filter_param.split('=')[0]
                val  = filter_param.split('=')[1]
                get_params[attr]= val
        return get_params
    
    def alerts(self, **kwargs):
        alert_url = self.api_root + "/api/alerts"
        get_params = None
        
        valid_params = {
            'filterstr' : alert_url + '?%s',
            'alertid' : alert_url + '/%s',
            'userid'    : self.api_root + '/api/users/%s/alerts',
            'ip'        : self.api_root + '/api/ips/%s/alerts',
            'machineid'   : self.api_root + '/api/machines/%s/alerts',
            'filesha1'  : self.api_root + '/api/files/%s/alerts', 
            'domain'    : self.api_root + '/api/domains/%s/alerts' 
        }
        (selector, selector_value) = self.__validate_arguments(kwargs, valid_params)
        
        if selector == 'filterstr':
            get_params = self.__prepare_param_dict_from_filter_str(selector_value)
            if get_params is not None:
                url = valid_params[selector] % urllib.parse.urlencode(get_params)             
        else:
            url = valid_params[selector] % selector_value        

        return self.__make_request(url)

    def machines(self, **kwargs):
        machine_url = self.api_root + "/api/machines"
        get_params = None
        
        valid_params = {
            'filterstr' : machine_url + '?%s',
            'machineid' : machine_url + '/%s',
            'userid'    : self.api_root + '/api/users/%s/machines',
            'ip'        : self.api_root + '/api/ips/%s/machines',
            'alertid'   : self.api_root + '/api/alerts/%s/machine',
            'filesha1'  : self.api_root + '/api/files/%s/machines', 
            'domain'    : self.api_root + '/api/domains/%s/machines',
            'ip_timestamp' : self.api_root + '/api/machines/findbyip(ip=\'%s\',timestamp=%s)'

        }
        
        (selector, selector_value) = self.__validate_arguments(kwargs, valid_params)

        if selector == 'ip_timestamp':
            url = valid_params[selector] % (selector_value.split('#')[0], selector_value.split('#')[1])
        elif selector == 'filterstr':
            get_params = self.__prepare_param_dict_from_filter_str(selector_value)
            if get_params is not None:
                url = valid_params[selector] % urllib.parse.urlencode(get_params)
        else:
            url = valid_params[selector] % selector_value

        return self.__make_request(url)
    
    def machine_actions(self, **kwargs):
        machineaction_url = self.api_root + "/api/machineactions"
        get_params = None
        
        valid_params = {
            'filterstr' : machineaction_url + '?%s',
            'actionid'  : machineaction_url + '/%s'
        }
        
        (selector, selector_value) = self.__validate_arguments(kwargs, valid_params)

        if selector == 'filterstr':
            get_params = self.__prepare_param_dict_from_filter_str(selector_value)
            if get_params is not None:
                url = valid_params[selector] % urllib.parse.urlencode(get_params)
        else:
            url = valid_params[selector] % selector_value

        return self.__make_request(url)

    def ips(self, **kwargs):
        ips_url = self.api_root + "/api/ips"
        
        valid_params = {
            'ip'    : ips_url + '/%s/stats'
        }
        
        (selector, selector_value) = self.__validate_arguments(kwargs, valid_params)
        
        url = valid_params[selector] % selector_value

        return self.__make_request(url)
    
    def users(self, **kwargs):
        user_url = self.api_root + "/api/users"
        
        valid_params = {
            'userid'    : user_url + '/%s',
            'machineid' : self.api_root + '/api/machines/%s/logonusers',
            'alertid'   : self.api_root + '/api/alerts/%s/user'
        }
        
        (selector, selector_value) = self.__validate_arguments(kwargs, valid_params)
        
        url = valid_params[selector] % selector_value

        return self.__make_request(url)
     
    def files(self, **kwargs):
        user_url = self.api_root + "/api/files/"
        
        valid_params = {
            'filehash' : user_url + '%s',
            'alertid'   : self.api_root + '/api/alerts/%s/files'
        }
        
        (selector, selector_value) = self.__validate_arguments(kwargs, valid_params)
        
        url = valid_params[selector] % selector_value

        return self.__make_request(url)
    
    def query(self, query):
        url = self.api_root + "/api/advancedqueries/run"
        data = json.dumps({ 'Query' : query }).encode("utf-8")
        req = urllib.request.Request(url, data, self.headers)
        response = urllib.request.urlopen(req)
        jsonResponse = json.loads(response.read())
        res = jsonResponse["Results"]
        if self.fUsePandas:
            return pd.io.json.json_normalize(res)
        return res
    
    def vtresults(self, hashlist):
        import requests 

        url = "https://www.virustotal.com/vtapi/v2/file/report"

        headers = {'User-Agent':'VirusTotal',
                    'Content-Type':'application/json'}
        if type(hashlist) == str:
            hashlist = [hashlist]
        
        data = {"resource": ','.join(hashlist),
                "apikey": self.vt_api_key}

        response = requests.get(url, data, headers=headers)

        jsonResponse = response.json()

        if self.fUsePandas:
            return pd.io.json.json_normalize(jsonResponse)
        return r.json()
