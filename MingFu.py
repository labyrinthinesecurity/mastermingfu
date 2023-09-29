#!/usr/bin/python3

import re,sys,json,os
import logging,urllib.request

BASE_URL = "https://graph.microsoft.com/v1.0"
token=None
membership={}
tenant_id=os.getenv('tenantid')
client_id=os.getenv('clientid')
client_secret=os.getenv('clientsecret')
scope=os.getenv('subscriptionid')
delegate=os.getenv('delegate')

def get_token(resource):
    data_body = (
        f"grant_type=client_credentials&client_id={client_id}"
        f"&client_secret={client_secret}&resource=https%3A%2F%2F{resource}%2F"
    )

    bindata = data_body.encode("utf-8")
    url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/token'
    req = urllib.request.Request(url=url, data=bindata, method='POST')

    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            return result.get('access_token')
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        logging.info(f"Error {e.code if hasattr(e, 'code') else e.reason}")
    return None

def azure_resource_query(query, url, token=None):
    if not token:
        token = get_token('management.azure.com')

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    if query:
        bindata = json.dumps(query).encode("utf-8")
        req = urllib.request.Request(url=url, data=bindata, method='POST', headers=headers)
    else:
        req = urllib.request.Request(url=url, method='GET', headers=headers)

    results = []
    total_records = 0

    try:
        with urllib.request.urlopen(req) as response:
            result_data = json.loads(response.read().decode())

            if 'totalRecords' in result_data:
                print(result_data['totalRecords'], "to process")

            if 'data' in result_data:
                total_records += len(result_data['data']['rows'])
                results = result_data['data']['rows']
            elif not query and 'value' in result_data:
                results = result_data['value']
                return results, token
            else:
                return result_data, token

            while '$skipToken' in result_data:
                skip_data, token = azure_resource_query_with_skip_token(query, url, token, result_data['$skipToken'])
                if 'data' in skip_data:
                    total_records += len(skip_data['data']['rows'])
                    results.extend(skip_data['data']['rows'])
                if skip_data.get('$skipToken') == result_data.get('$skipToken'):
                    del result_data['$skipToken']

            return results, token

    except (urllib.error.HTTPError, urllib.error.URLError, urllib.error.InvalidURL) as e:
        if str(e.code) == '503':
            time.sleep(5)
    except (ConnectionResetError, TimeoutError, Exception) as e:
        print(f"A {type(e).__name__} occurred: {e}")

    return None, token

def microsoft_graph_query(url, token=None):
    if not token:
        token = get_token('graph.microsoft.com')

    logging.info("NEW query")
    headers = {'Authorization': f'Bearer {token}'}
    req = urllib.request.Request(url=url, method='GET', headers=headers)

    try:
        with urllib.request.urlopen(req) as response:
            logging.info(f"response {response.code}")
            result = json.loads(response.read().decode())
            return result, token
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        logging.info(f"Error {e.code if hasattr(e, 'code') else e.reason}")
    return None, token

def entity_exists(principal_id, token):
    base_url = "https://graph.microsoft.com/v1.0"
    endpoints = [("groups", "group"),
                 ("users", "user"),
                 ("applications", "app"),
                 ("servicePrincipals", "SPN")]

    for endpoint, entity_type in endpoints:
        url = f"{base_url}/{endpoint}/{principal_id}"
        result, token = microsoft_graph_query(url, token)

        if result:
            display_name = result.get('displayName', '')
            return result, token, entity_type, display_name
    return None, token, None, None

def get_all_groups(principal_id, principal_type, token=None):
    if not token:
        token = get_token('graph.microsoft.com')

    type_mapping = {
        "SPN": f"{BASE_URL}/servicePrincipals/{principal_id}/transitiveMemberOf",
        "user": f"{BASE_URL}/users/{principal_id}/transitiveMemberOf"
    }

    url = type_mapping.get(principal_type)

    if not url:
        return None  # or raise an error if an unknown type is a critical issue

    result, _ = microsoft_graph_query(url, token)
    return result

def unfold(group_id, token=None):
    if not token:
        token = get_token('graph.microsoft.com')

    principals = []
    if group_id not in membership:
        url = f"{BASE_URL}/groups/{group_id}"
        result, token = microsoft_graph_query(url, token)
        if result is None:
            print(f"WARNING: unknown group {group_id}")
            return [], token

        membership[group_id] = {
            'principalType': 'Group',
            'principalId': result['id'],
            'displayName': result['displayName'],
            'groups': []
        }

    url = f"{BASE_URL}/groups/{group_id}/members"
    result, token = microsoft_graph_query(url, token)

    for principal in result.get('value', []):
        principal_id = principal['id']

        if principal_id not in membership:
            odata_type = principal.get('@odata.type')
            principal_type = 'User' if odata_type == '#microsoft.graph.user' else 'Group' if odata_type == '#microsoft.graph.group' else None

            membership[principal_id] = {
                'principalType': principal_type,
                'displayName': principal.get('displayName'),
                'principalId': principal_id,
                'groups': []
            }

            if principal_type == 'Group':
                nested_principals, token = unfold(principal_id, token)
                principals.extend(nested_principals)

        membership[principal_id]['groups'].append(group_id)
        principals.append(principal_id)

    return principals, token


def modify_RBAC(role_def):
    permissions = role_def.get('properties', {}).get('permissions', [])
    for permission in permissions:
        actions = permission.get('actions', [])
        for action in actions:
            if action.startswith('Microsoft.Authorization/') and not action.endswith('/read'):
                return True
    return False

def parse_condition(condition_str):
    action_based_condition_pattern = r"\(\(!\(ActionMatches\{'(.*?)'\}\)(.*?)\)\)"
    role_def_id_pattern = rf"@(?:Request|Resource)\[Microsoft.Authorization/roleAssignments:RoleDefinitionId\]\s+ForAnyOfAnyValues:GuidEquals\s+\{{([^}}]+)\}}"
    principal_id_pattern = rf"@Request\[Microsoft.Authorization/roleAssignments:PrincipalId\]\s+ForAnyOfAnyValues:GuidEquals\s+\{{([^}}]+)\}}"
    principal_type_string_pattern = rf"@(?:Request|Resource)\[Microsoft.Authorization/roleAssignments:PrincipalType\]\s+ForAnyOfAnyValues:String(?:Not)?EqualsIgnoreCase\s+\{{'(User|Group|ServicePrincipal)'\}}"

    action_conditions = re.findall(action_based_condition_pattern, condition_str)

    result = {}

    for action, condition in action_conditions:
        role_def_ids_matches = re.findall(role_def_id_pattern, condition)
        role_def_ids = [id_.strip() for match in role_def_ids_matches for id_ in match.split(',')]

        principal_id_match = re.search(principal_id_pattern, condition)
        principal_ids = [id_.strip() for id_ in principal_id_match.group(1).split(',')] if principal_id_match else None

        principal_type_string_match = re.search(principal_type_string_pattern, condition)
        principal_type_string = principal_type_string_match.group(1) if principal_type_string_match else None

        result[action] = {
            'role_definition_ids': role_def_ids,
            'principal_ids': principal_ids,
            'principal_type_string': principal_type_string
        }

    return result

token=get_token('graph.microsoft.com')
ARtoken=None
delegates=[ delegate ]
groups={}

def prove(token):
  global groups
  for d in delegates:
    gr=get_all_groups(d,'user',token)
    groups[d]=set([])
    for g in gr['value']:
      groups[d].add(g['id'])
prove(token)

print("+================================================+")
print("|  Master MingFu, 0.0.1 (Preview)                |")
print("|  github.com/labyrinthinesecurity/mastermingfu  |")
print("|                                                |")
print("|  DISCLAIMER: use at your own risks             |")
print("+================================================+")
print("")
print("tenant ID",tenant_id)
print("delegate ID",delegate)
print("delegate scope",scope,"(only subscription scope are currently supported)")
print("")
condition_str=input("Enter RBAC condition:")

if len(condition_str)<1:
  condition_str="((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {4d97b98b-1d4f-4787-a291-c67834d212e7, 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9} AND @Request[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidEquals {03107740-5e00-11ee-b42c-000d3a23479d, "+delegate+"})) AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {4d97b98b-1d4f-4787-a291-c67834d212e7, 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9} AND @Resource[Microsoft.Authorization/roleAssignments:PrincipalType] ForAnyOfAnyValues:StringNotEqualsIgnoreCase {'ServicePrincipal'}))"
  print("Unknown condition. Resorting to test condition")
  print(condition_str)
parsed_data = parse_condition(condition_str)
print("")
print("parsed condition:")
print(parsed_data)
print("")

print("Identifying SOD vioations...")

if 'Microsoft.Authorization/roleAssignments/write' in parsed_data:
  if parsed_data['Microsoft.Authorization/roleAssignments/write']['principal_ids'] is not None:
    for apid in parsed_data['Microsoft.Authorization/roleAssignments/write']['principal_ids']:
      rez,token,ztype,zdn=entity_exists(apid,token)
      if rez is not None:
        if ztype=='user':
          for d in delegates:
            if d==apid:
              print("SOD violation: delegate",d,"assigns himself a role")
              break
        elif ztype=='group':
          for d in delegates:
            for g in groups[d]:
              if g==apid:
                print("SOD violation: delegate",d,"belongs to group",g)
                break
        elif ztype=='SPN':
          print("SPN")

if 'Microsoft.Authorization/roleAssignments/write' in parsed_data:
  if parsed_data['Microsoft.Authorization/roleAssignments/write']['principal_type_string'] is not None:
    if parsed_data['Microsoft.Authorization/roleAssignments/write']['principal_type_string']=='User':
      print("SOD violation: delegates belongs to Users")

  if parsed_data['Microsoft.Authorization/roleAssignments/write']['role_definition_ids'] is not None:
    for rdid in parsed_data['Microsoft.Authorization/roleAssignments/write']['role_definition_ids']:
      url='https://management.azure.com/subscriptions/'+scope+'/providers/Microsoft.Authorization/roleDefinitions/'+rdid+'?api-version=2022-04-01'
      rd,ARtoken=azure_resource_query(None,url,ARtoken)
      if modify_RBAC(rd):
          print("SOD violation: role",rd['id'],"gives RBAC admin roles")

print("")
print("Note: Master MingFu is in ALPHA. Some important vioations are not implemented, eg:")
print("* MingFu does not check if delegate attempts to assign an operational role to one of her user-assigned MI")
print("* MingFu does not handle complex boolean conditions")
print("* MingFu does not handle collusion scenarios involving several delegates")
print("* ...")
