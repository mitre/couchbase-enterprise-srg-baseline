# encoding: UTF-8
control "V-58061" do
  desc  "rationale", ""
  desc  "check", "
    If the application owner has determined that the need for system
availability does not outweigh the need for a complete audit trail, this is not
applicable (NA).
    Once enabled on the cluster, Couchbase auditing provides log rotation (i.e.
Rotate interval and Rotate size) option by default. This ensures that the audit
log does not consume too much disk space.
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
    Enable session auditing on the Couchbase cluster.
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
  tag "gtitle": "SRG-APP-000109-DB-000321"
  tag "gid": "V-58061"
  tag "rid": "SV-72491r1_rule"
  tag "stig_id": "SRG-APP-000109-DB-000321"
  tag "fix_id": "F-63269r1_fix"
  tag "cci": ["CCI-000140"]
  tag "nist": ["AU-5 b", "Rev_4"]
end
