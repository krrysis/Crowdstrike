Author: Kshitij Shukla
GIT: https://github.com/krrysis
email: kshitijshukla345@gmail.com

# Crowdstrike
Scripts leveraging CS apis to acheive various tasks for automation.

# HOST MANAGEMENT
# crowdstrike_host_hider.py
Script to hide/delete hosts in CS
input host ids into the csv host_ids.csv 
put id&secret for the respective cid.
Logging is enabled, check logs for any errors.

# FIREWALL MANAGEMENT
# FirewallRuleGroupAPIMigration.py
Script to copy firewall rule groups cross tenant. Leverages 3 Endpoints
GET rulegroup details
GET rule details
POST create rules
Preq: must have source & destination client id & client secret with scope permission as Firewall Management Read & Write.