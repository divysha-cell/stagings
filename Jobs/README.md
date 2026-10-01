## Google Chronicle Alerts Creator Job
This job will sync new SOAR alerts with Chronicle SIEM.
Note: This job is only supported from Chronicle SOAR version 6.2.30 and higher.


**Run Interval In Seconds:** 60

#### Parameters
|Name|Type|Is Mandatory|Value|
|----|----|------------|-----|
|Environment|String|True|Default Environment|
|API Root|String|True|https://staging-chronicle.sandbox.googleapis.com/v1alpha/projects/spsstg-j2nis/locations/us/instances/fa12d79f-1170-4476-8f19-7939caa290d1|
|User's Service Account|Password|False|*****|
|Workload Identity Email|Password|False|*****|
|Verify SSL|Boolean|False|true|

## Google Chronicle Sync Job
This job will synchronize information about Chronicle SOAR Cases and Chronicle SOAR Alerts with Chronicle SIEM.
 Note: This job is only supported from Chronicle SOAR version 6.1.44 and higher.


**Run Interval In Seconds:** 60

#### Parameters
|Name|Type|Is Mandatory|Value|
|----|----|------------|-----|
|Environment|String|True|Default Environment|
|API Root|String|True|https://staging-chronicle.sandbox.googleapis.com/v1alpha/projects/spsstg-j2nis/locations/us/instances/fa12d79f-1170-4476-8f19-7939caa290d1|
|User's Service Account|Password|False|*****|
|Workload Identity Email|Password|False|*****|
|Max Hours Backwards|String|False|24|
|Verify SSL|Boolean|False|true|

## Sync Alerts
This job will synchronize Google SecOps Alerts and Crowdstrike alerts. The job synchronizes comments and status. Requires “Crowdstrike Alert” tag on the case. Note: If the alert didn’t originate from “Alerts Connector” or “Identity Protections Detection Connector” you will need to add an “Alert_ID” context value for the job to be able to find the correct information.


**Run Interval In Seconds:** 3600

#### Parameters
|Name|Type|Is Mandatory|Value|
|----|----|------------|-----|
|Environment Name|String|True|Default Environment|
|API Root|String|True|https://api.crowdstrike.com|
|Client ID|String|True|s|
|Client Secret|Password|True|*****|
|Max Hours Backwards|Int|False|24|
|Verify SSL|Boolean|False|true|

## stage1pjob
This job synchronizes 


**Run Interval In Seconds:** 600

#### Parameters
|Name|Type|Is Mandatory|Value|
|----|----|------------|-----|
|Environment Name|String|True|Default Environment|
|Api Root|String|False|https://api-gcptesting.xdr.us.paloaltonetworks.com|
|Api Key|Password|True|*****|
|Api Key ID|String|True|56|
|Max Hours Backwards|Int|True|24|
|User Mapping JSON|String|False|{"Google SecOps Display Name": "XDR Username"}|
|Verify SSL|Boolean|False|true|

