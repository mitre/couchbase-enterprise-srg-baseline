# encoding: UTF-8

control "V-58109" do
  title "Couchbase must generate audit records when unsuccessful logons or
connection attempts occur."
  desc  "For completeness of forensic analysis, it is necessary to track failed
attempts to log on to Couchbase. While positive identification may not be
possible in a case of failed authentication, as much information as possible
about the incident must be captured."
  desc  "rationale", ""
  desc  "check", "
    When enabled on the cluster, Couchbase auditing is capable of logging
unsuccessful logins and connections by default.
    Couchbase Server 6.5.0 and earlier -
      As root or a sudo user, verify that the \"audit.log\" file exists in the
var/lib/couchbase/logs directory of the Couchbase application home (example:
/opt/couchbase/var/lib/couchbase/logs) and is populated with data captured.
      Review the audit.log file. If it does not exist or is not populated with
data captured, this is a finding.
    Couchbase Server Version 6.5.1 and later -
      As the Full Admin, verify that auditing is enabled by executing the
following command:
       $ couchbase-cli setting-audit -c <host>:<port> -u <Full Admin> -p
<Password> --get-settings
      Review the output of the command. If \"Audit enabled\" is not set to
\"true\", this is finding.
  "
  desc  "fix", "
    Enable session auditing on the Couchbase cluster to produce audit records
when unsuccessful login or connections occur.
    Couchbase Server 6.5.0 and earlier -
      As the Full Admin, execute the following command to enable auditing:
       $ couchbase-cli setting-audit --cluster <host>:<port> --u <Full Admin>
--password <Password> --audit-enabled 1 --audit-log-rotate-interval 604800
--audit-log-path /opt/couchbase/var/lib/couchbase/logs
    Couchbase Server Version 6.5.1 and later -
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
end
