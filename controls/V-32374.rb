# encoding: UTF-8
control "V-32374" do
  desc  "rationale", ""
  desc  "check", "
    Once enabled on the cluster, Couchbase auditing provides the following
fields by default:
      - \"id\" - ID of Event
      - \"name\" - Name of Event (can indicate success/failure)
      - \"description\" - Event Description (can indicate success/failure)
      - \"filtering_permitted\" - Whether the event is filterable
      - \"mandatory_fields\" - Includes \"timestamp\" (UTC time and ISO 8601
format) and \"user\" fields
    Note that different event-types generate different field-subsets. Below are
some of the fields provided:
      - \"node_id\" - ID of Node
      - \"session_id\" - ID of current Session
      - \"ip\" - Remote IP address
      - \"port\" - Remote port
      - \"bucket_name\" - Name of Bucket
    Couchbase Server 6.5.0 and earlier -
      As root or a sudo user, verify that the \"audit.log\" file exists in the
var/lib/couchbase/logs directory of the Couchbase application home (example:
/opt/couchbase/var/lib/couchbase/logs) and is populated with data captured.
      Review the audit.log file. If it does not exist or not populated with
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
    Enable session auditing on the Couchbase cluster to produce sufficient
information regarding the user/subject or process associated with the event.
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
  tag "gtitle": "SRG-APP-000100-DB-000201"
  tag "gid": "V-32374"
  tag "rid": "SV-42711r3_rule"
  tag "stig_id": "SRG-APP-000100-DB-000201"
  tag "fix_id": "F-36288r3_fix"
  tag "cci": ["CCI-001487"]
  tag "nist": ["AU-3", "Rev_4"]
end
