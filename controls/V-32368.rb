# encoding: UTF-8

control "V-32368" do
  title "Couchbase must produce audit records containing sufficient information
to establish what type of events occurred."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without establishing what type of event occurred, it would
be difficult to establish, correlate, and investigate the events relating to an
incident or identify those responsible for one.

    Audit record content that may be necessary to satisfy the requirement of
this policy includes, for example, time stamps, user/process identifiers, event
descriptions, success/fail indications, filenames involved, and access control
or flow control rules invoked.

    Associating event types with detected events in the application and audit
logs provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
application.

    Database software is capable of a range of actions on data stored within
the database. It is important, for accurate forensic analysis, to know exactly
what actions were performed. This requires specific information regarding the
event type an audit record is referring to. If event type information is not
recorded and stored with the audit record, the record itself is of very limited
use.
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
  tag "gtitle": "SRG-APP-000095-DB-000039"
  tag "gid": "V-32368"
  tag "rid": "SV-42705r3_rule"
  tag "stig_id": "SRG-APP-000095-DB-000039"
  tag "fix_id": "F-36283r3_fix"
  tag "cci": ["CCI-000130"]
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
