# encoding: UTF-8

control "V-32369" do
  title "Couchbase must produce audit records containing time stamps to
establish when the events occurred."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without establishing when events occurred, it is impossible
to establish, correlate, and investigate the events relating to an incident.

    In order to compile an accurate risk assessment and provide forensic
analysis, it is essential for security personnel to know the date and time when
events occurred.

    Associating the date and time with detected events in the application and
audit logs provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
application.

    Database software is capable of a range of actions on data stored within
the database. It is important, for accurate forensic analysis, to know exactly
when specific actions were performed. This requires the date and time an audit
record is referring to. If date and time information is not recorded and stored
with the audit record, the record itself is of very limited use.
  "
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
    Couchbase Server Version 6.51 and later -
      As the Full Admin, verify that auditing is enabled by executing the
following command:
       $ couchbase-cli setting-audit -c <host>:<port> -u <Full Admin> -p
<Password> --get-settings
      Review the output of the command. If \"Audit enabled\" is not set to
\"true\", this is finding.
  "
  desc  "fix", "
    Enable session auditing on the Couchbase cluster to produce sufficient
information regarding when the events occurred.
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
  tag "gtitle": "SRG-APP-000096-DB-000040"
  tag "gid": "V-32369"
  tag "rid": "SV-42706r3_rule"
  tag "stig_id": "SRG-APP-000096-DB-000040"
  tag "fix_id": "F-36284r3_fix"
  tag "cci": ["CCI-000131"]
  tag "nist": ["AU-3", "Rev_4"]

  couchbase_version = command('couchbase-server -v').stdout

  if couchbase_version.include?("6.5.1") || couchbase_version.include?("6.6.0")
    describe command("couchbase-cli setting-audit -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --get-settings | grep 'Audit enabled:'") do
      its('stdout') { should include "True" }
    end 
  else
    describe file(input('cb_audit_log')) do
      it {should exist}
    end
  end
end
