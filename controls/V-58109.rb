# encoding: UTF-8

control "V-58109" do
  title "Couchbase must generate audit records when unsuccessful logons or
  connection attempts occur."
  desc  "For completeness of forensic analysis, it is necessary to track failed
  attempts to log on to Couchbase. While positive identification may not be
  possible in a case of failed authentication, as much information as possible
  about the incident must be captured."
  desc  "check", "
  When enabled on the cluster, Couchbase auditing is capable of logging 
  unsuccessful logins and connections by default. 

  As the Full Admin, verify that auditing is enabled by executing the 
  following command:

  $ curl -v -X GET -u <Full Admin>:<Password> http://<host>:<port>/settings/audit

  Verify from the output that \"auditEnabled\" is set to \"true\". 
  If  \"auditEnabled\" is not set to \"true\", this is finding.
  "
  desc  "fix", "
  Enable session auditing on the Couchbase cluster to produce sufficient
  information regarding the types of events that have occurred.

  Couchbase Server 6.5.0 and earlier -
  As the Full Admin, execute the following command to enable auditing:
    $ couchbase-cli setting-audit --cluster <host>:<port> --u <Full Admin>
    --password <Password> --audit-enabled 1 --audit-log-rotate-interval 604800
    --audit-log-path /opt/couchbase/var/lib/couchbase/logs

  Couchbase Server Version 6.51 and later -
  As the Full Admin, execute the following command to enable auditing:
    $ couchbase-cli setting-audit --cluster <host>:<port> --u <Full Admin>
    --password <Password> --set  --audit-enabled 1 --audit-log-rotate-interval
    604800 --audit-log-path /opt/couchbase/var/lib/couchbase/logs
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000503-DB-000351"
  tag "gid": "V-58109"
  tag "rid": "SV-72539r1_rule"
  tag "stig_id": "SRG-APP-000503-DB-000351"
  tag "fix_id": "F-63317r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  
  describe "Couchbase log auditing should be enabled." do
    subject { json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
    http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/audit") }
    its('auditdEnabled') { should eq true }
  end 
end
