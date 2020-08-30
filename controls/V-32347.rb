# encoding: UTF-8
control "V-32347" do
  desc  "rationale", ""
  desc  "check", "
    Review system documentation to determine the data and the actions on data
that need to be protected from repudiation by means of audit trails.
    When enabled, Couchbase can identify a unique user for each record.
    Couchbase Server 6.5.0 and earlier -
      As root or a sudo user, verify that the \"audit.log\" file exists in the
var/lib/couchbase/logs directory of the Couchbase application home (example:
/opt/couchbase/var/lib/couchbase/logs) and is populated with data captured.
    Couchbase Server Version 6.51 and later -
      As the Full Admin, verify that auditing is enabled by executing the
following command:
       $ couchbase-cli setting-audit -c <host>:<port> -u <Full Admin> -p
<Password> --get-settings
      Verify from the output that \"Audit enabled\" is set to \"true\". If
\"Audit enabled\" is not set to true, this is finding.
  "
  desc  "fix", "
    Use accounts assigned to individual users. Where the application connects
to Couchbase using a standard, shared account, ensure that it also captures the
individual user identification and passes it to Couchbase.
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
  tag "gtitle": "SRG-APP-000080-DB-000063"
  tag "gid": "V-32347"
  tag "rid": "SV-42684r4_rule"
  tag "stig_id": "SRG-APP-000080-DB-000063"
  tag "fix_id": "F-36261r3_fix"
  tag "cci": ["CCI-000166"]
  tag "nist": ["AU-10", "Rev_4"]
end
