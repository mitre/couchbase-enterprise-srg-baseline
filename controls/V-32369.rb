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

  As the Full Admin, create a user account by executing the following command:
    $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \
    -p <Password> --set --rbac-username jdoe --rbac-password cbpass \
    --rbac-name \"John Doe\" --roles replication_admin \
    --auth-domain local
      
  Verify that the event logged contains the required fields:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log 
      
  If the log does not contain the \"timestamp\" field,
  this is a finding.
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

  describe "Create the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username jdoe --rbac-password cbpass --rbac-name 'John Doe' \
    --roles replication_admin --auth-domain local") }
    its('exit_status') { should eq 0 }
  end

  describe "The logged event should contain required fields. The" do
    subject { command("grep 'jdoe' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /"timestamp"/}
  end

  describe "Delete the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --delete --rbac-username jdoe --auth-domain local") }
    its('exit_status') { should eq 0 }
  end
end
