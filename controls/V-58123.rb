# encoding: UTF-8

control "V-58123" do
  title "Couchbase must generate audit records for all direct access to the
database(s)."
  desc  "In this context, direct access is any query, command, or call to
Couchbase that comes from any source other than the application(s) that it
supports. Examples would be the command line or a database management utility
program. The intent is to capture all activity from administrative and
non-standard sources."
  desc  "check", "
    If Couchbase does not generate audit records for all direct access to the
database(s), this is a finding.
    Couchbase Server 6.5.0 and earlier-
    Verify that the \"http_access.log\" and \"http_access_internal.log\" files
exists in the Couchbase log directory. If the logs do not exist or do not
generate records, this is a finding.
    Couchbase Server Version 6.5.1 and later-
    Verify that auditing is enabled:
    $ couchbase-cli setting-audit -c <host>:<port> -u <Full Admin> -p
<Password> --get-settings
    Review the output. If \"Audit enabled\" is not true, this is finding.
  "
  desc  "fix", "
    Configure Couchbase to generate audit records for all direct access to the
database(s).
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
  tag "gtitle": "SRG-APP-000508-DB-000358"
  tag "gid": "V-58123"
  tag "rid": "SV-72553r1_rule"
  tag "stig_id": "SRG-APP-000508-DB-000358"
  tag "fix_id": "F-63331r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end
