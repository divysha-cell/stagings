
# CaServiceDesk

CA Service Desk Manager is designed to help IT service desk analysts make every moment count through a dynamic experience so they can deliver great customer service without the fear of overbearing processes or metrics. With the solution, teams can embrace teamwork rather than working from siloed knowledge stashes and disjointed communications.

Python Version - V3_11
#### Parameters
|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|Api Root||True|String|http://<IP OR FQDN>:<PORT>/|
|Username||True|String|None|
|Password||True|Password|*****|
|Ticket Fields||True|String|customer.combo_name,category.sym,status.sym,priority.sym,active,log_agent.combo_name,assignee.combo_name,group.combo_name,affected_service.name,severity.sym,urgency.sym,impact.sym,problem.ref_num,resolution_code.sym,call_back_date,change.chg_ref_num,caused_by_chg.chg_ref_num,external_system_ticket,resolution_method.sym,symptom_code.sym,requested_by.combo_name,persistent_id,summary,description,open_date,last_mod_dt,resolve_date,close_date,ref_num|


#### Dependencies
| |
|-|
|arrow-1.4.0-py3-none-any.whl|
|idna-3.13-py3-none-any.whl|
|lxml-6.1.0-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.whl|
|python_dateutil-2.9.0.post0-py2.py3-none-any.whl|
|requests-2.33.1-py3-none-any.whl|
|six-1.17.0-py2.py3-none-any.whl|
|attrs-26.1.0-py3-none-any.whl|
|requests_toolbelt-1.0.0-py2.py3-none-any.whl|
|pytz-2026.1.post1-py2.py3-none-any.whl|
|platformdirs-4.9.6-py3-none-any.whl|
|defusedxml-0.7.1-py2.py3-none-any.whl|
|chardet-7.4.3-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl|
|zeep-4.2.1-py3-none-any.whl|
|isodate-0.7.2-py3-none-any.whl|
|certifi-2026.4.22-py3-none-any.whl|
|requests_file-3.0.1-py2.py3-none-any.whl|
|urllib3-2.6.3-py3-none-any.whl|
|tzdata-2026.2-py2.py3-none-any.whl|
|TIPCommon-1.0.12-py2.py3-none-any.whl|
|charset_normalizer-3.4.7-cp311-cp311-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl|


## Actions
#### Add Comment
Add comment to a CA ServiceDesk incident
Timeout - 600 Seconds


|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|Ticket ID|Incident's ref num. e.g. 338|True|String||
|Comment|Comment to add to an incident|True|String||



#### Sync Ticket History
Fetch and attach the entire ticket history to an alert
Timeout - 600 Seconds


|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|Comment Type Field|Ticket type. e.g. type.sym|False|String||
|Analyst Name Field|Analyst Name. e.g. analyst.combo_name|False|String||
|TimeStamp Field|Time field e.g. time_stamap.|False|String||



##### JSON Results
```json
[{"time_stamp": "1546944096", "analyst.combo_name": "Analyst", "type.sym": "Log Comment", "description": "Tests Comments."}]
```



#### Change Ticket Status
Change CA Desk Manager ticket status
Timeout - 600 Seconds


|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|Ticket ID|Incident number|True|String||
|Status|Incident status to change. e.g. Closed|True|String||



#### Search Tickets
Search tickets in CA Desk Manager by field
Timeout - 600 Seconds


|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|Incident ID|Incident ID to filter by|False|String|None|
|Summary|Summary content to filter by|False|String|None|
|Description|Description content to filter by |False|String|None|
|Status|Filter by status. e.g. Open|False|String||
|Days Backwards|Get results from 'x' days backwards. e.g. 5'|False|String||



##### JSON Results
```json
[{"severity.sym": "None", "resolution_code.sym": "None", "group.combo_name": "None", "resolve_date": "None", "caused_by_chg.chg_ref_num": "None", "log_agent.combo_name": "TEST", "requested_by.combo_name": "None", "resolution_method.sym": "None", "problem.ref_num": "None", "change.chg_ref_num": "None", "affected_service.name": "None", "priority.sym": "3", "customer.combo_name": "TEST", "call_back_date": "None", "assignee.combo_name": "TestUser", "status": "OP", "urgency.sym": "Test", "impact.sym": "Test Group", "description": "test", "symptom_code.sym": "None", "external_system_ticket": "None", "last_mod_dt": "1547368725", "active": "1", "open_date": "1517743983", "category.sym": "None", "status.sym": "Open", "persistent_id": "cr:123456", "summary": "test", "close_date": "None"}]
```



#### Close Ticket
Close incident in CA ServiceDesk manager
Timeout - 600 Seconds


|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|Ticket ID|Incident number|True|String||
|Close Reason|description which can be used in the Close activity log.|True|String||



#### Assign To Group
Assign an incident to a particular group
Timeout - 600 Seconds


|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|Ticket ID|Incident number|True|String||
|Group|Group to assign the incident to|True|String||



#### Ping
Test Connectivity
Timeout - 600 Seconds



#### Wait For Status Change
Waiting until ticket status is changed.
Timeout - 600 Seconds


|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|Ticket ID|Target ticket ID.|True|String||
|Expected Ticket Status Name|Expected status.|True|String||



##### JSON Results
```json
{"severity.sym": "None", "resolution_code.sym": "None", "urgency.sym": "Test", "resolve_date": "None", "caused_by_chg.chg_ref_num": "None", "log_agent.combo_name": "Test", "requested_by.combo_name": "None", "resolution_method.sym": "None", "problem.ref_num": "None", "change.chg_ref_num": "None", "affected_service.name": "None", "priority.sym": "3", "customer.combo_name": "Test", "call_back_date": "None", "assignee.combo_name": "TestUser", "status": "OP", "group.combo_name": "None", "impact.sym": "Test Group", "description": "Test", "symptom_code.sym": "None", "external_system_ticket": "None", "last_mod_dt": "1547368725", "active": "1", "open_date": "1517743983", "category.sym": "None", "status.sym": "Open", "persistent_id": "cr:123456", "summary": "test", "close_date": "None"}
```



#### Create Ticket
Create new ticket in CA ServiceDesk.
Timeout - 600 Seconds


|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|Summary|Incident's summary text|True|String||
|Description|Incident's description text|True|String||
|Category Name|Incident's area name. e.g. Software|True|String||
|Group Name|Group name. e.g. Test|True|String||
|Username|User name|True|String||
|Custom Fields|Specify a JSON object containing all of the needed fields and values. The structure is the following: {"field”:”value"}. If the same field is provided in the “Custom Fields“ parameter and other parameters, the “Custom Fields“  parameter value has priority.|False|String||



#### Assign Incident To User
Assign an incident to a specific user
Timeout - 600 Seconds


|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|Ticket ID|Incident number|True|String||
|Username|Username to assign the incident to.|True|String||






## Jobs

#### Sync Comments
Sync comments from CA Desk Manager to Siemplify.

|Name|IsMandatory|Type|DefaultValue|
|----|-----------|----|------------|
|API Root|True|String|http://x.x.x.x:<port>|
|Username|True|String||
|Password|True|Password|*****|
|Summery Field|True|String|summery.combo_name|
|Ticket Fields|True|String|summery.combo_name,customer.combo_name,category.sym,status.sym,priority.sym,active,log_agent.combo_name,assignee.combo_name,group.combo_name,affected_service.name,severity.sym,urgency.sym,impact.sym,problem.ref_num,resolution_code.sym,call_back_date,change.chg_ref_num,caused_by_chg.chg_ref_num,external_system_ticket,resolution_method.sym,symptom_code.sym,requested_by.combo_name,persistent_id,summary,description,open_date,last_mod_dt,resolve_date,close_date,ref_num|
|Script Name|True|String|Test|
|Ticket Type Field|False|Boolean||
|Analyst Type Field|False|Boolean||
|Time Stamp Field|False|Boolean||
|Timezone String|False|Boolean|UTC|

#### CA Close Ticket In CA For Closed Case
Sync closure of the tickets at the CA Desk Manager with Siemplify cases closure.

|Name|IsMandatory|Type|DefaultValue|
|----|-----------|----|------------|
|Group Field|True|String|group.combo_name|
|API Root|True|String|http://x.x.x.x:<port>|
|Username|True|String||
|Password|True|String||
|Group Filter|False|String|Test|
|Ticket Final Status|True|String|Closed|
|Script Name|True|String|TEST CLOSE|



## Connectors
#### CA Service Desk Connector
Fetch tickets from CA Desk Manager.

|Name|Description|IsMandatory|Type|DefaultValue|
|----|-----------|-----------|----|------------|
|API Root|e.g. http://x.x.x.x:8080|True|String||
|Username|Username|True|String||
|Password|Password|True|Password|*****|
|Ticket ID Field|Incident id field key as it appear at the ticket JSON e.g. ref_num|True|String|ref_num|
|Start Time Field|Represent the key of the start time at the ticket. e.g. open_date|True|String|open_date|
|End Time Field|Represent the key of the end time at the ticket. e.g. last_mod_dt|True|String|last_mod_dt|
|Category Default Field|Represent the category key at the ticket. e.g. category|True|String|category|
|Category Fallback Field|e.g. category.sym|True|String|category.sym|
|User ID Field|Filter by user. e.g. customer.combo_name|True|String|customer.combo_name|
|Ticket Fields|Comma separated. e.g. customer.combo_name,category.sym,status.sym,priority.sym,active,log_agent.combo_name,assignee.combo_name,group.combo_name,affected_service.name,severity.sym,urgency.sym,impact.sym,problem.ref_num,resolution_code.sym,call_back_date,change.chg_ref_num,caused_by_chg.chg_ref_num,external_system_ticket,resolution_method.sym,symptom_code.sym,requested_by.combo_name,persistent_id,summary,description,open_date,last_mod_dt,resolve_date,close_date,ref_num|True|String|customer.combo_name,category.sym,status.sym,priority.sym,active,log_agent.combo_name,assignee.combo_name,group.combo_name,affected_service.name,severity.sym,urgency.sym,impact.sym,problem.ref_num,resolution_code.sym,call_back_date,change.chg_ref_num,caused_by_chg.chg_ref_num,external_system_ticket,resolution_method.sym,symptom_code.sym,requested_by.combo_name,persistent_id,summary,description,open_date,last_mod_dt,resolve_date,close_date,ref_num|
|List Of Users To Ignore|Comma separated. Filter incidents by users to ignore|False|String||
|Categories List|Filter incidents by categories|False|String||
|Groups List|Filter incidents by groups|False|String||
|Proxy Server Address|The address of the proxy server to use.|False|String||
|Proxy Username|The proxy username to authenticate with.|False|String||
|Proxy Password|The proxy password to authenticate with.|False|Password|*****|




