# stage1pplaybook




**Enabled:** False

**Version:** 1

**Type:** Playbook

**Priority:** 2

**Playbook Simulator:** False



### Playbook Trigger
**Trigger Type:** All

**Conditions Operator:** And

##### Conditions
|Key|Operator|Value|
|---|--------|-----|
|None|Equals|None|



### Involved Steps (Unordered)
|Step Name|Description|Integration|Original Action|
|---------|-----------|-----------|---------------|
|Siemplify_Case Comment_2|Add a comment to the case the current alert has been grouped to|Siemplify|Case Comment|
|Siemplify_Case Tag_1|Add given tag to the case the current alert is grouped to|Siemplify|Case Tag|
|GitSync_Ping_1|Test connectivity to GitSync|GitSync|Ping|
|Siemplify_Case Comment_3|Add a comment to the case the current alert has been grouped to|Siemplify|Case Comment|
|Siemplify_Case Comment_1|Add a comment to the case the current alert has been grouped to|Siemplify|Case Comment|
|Siemplify_Case Tag_2|Add given tag to the case the current alert is grouped to|Siemplify|Case Tag|

### Involved Blocks
|Name|Description|
|----|-----------|
|stage1pblock|An embedded workflow that can receive inputs and return an output.|
