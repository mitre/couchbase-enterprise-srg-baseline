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
      
  Note that different event-types generate different field-subsets. Below are some 
  additional fields provided to establish what type of events occured. 
    - \"real_userid\" - User Account Information
    
  As the Full Admin, create a user account by executing the following command:
    $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \
    -p <Password> --set --rbac-username jdoe --rbac-password @dminP@asswd2020 \
    --rbac-name \"John Doe\" --roles replication_admin \
    --auth-domain local
    
  Verify that the event logged contains the required fields:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log 
    
  If the log does not contain the \"description\", \"timestamp\", and \"real_userid\" 
  fields, this is a finding.
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
  
  describe "Create the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username jdoe --rbac-password doe_cbP@ssw0rd2020 --rbac-name 'John Doe' \
    --roles replication_admin --auth-domain local") }
    its('exit_status') { should eq 0 }
  end

  describe "The logged event should contain required fields. The" do
    subject { command("grep 'jdoe' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /"description"/}
    its('stdout') { should match /"timestamp"/}
    its('stdout') { should match /"real_userid"/}
  end

  describe "Delete the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --delete --rbac-username jdoe --auth-domain local") }
    its('exit_status') { should eq 0 }
  end
end
