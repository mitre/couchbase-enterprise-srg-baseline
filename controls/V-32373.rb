# encoding: UTF-8

control "V-32373" do
  title "Couchbase must produce audit records containing sufficient information
to establish the outcome (success or failure) of the events."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without information about the outcome of events, security
personnel cannot make an accurate assessment as to whether an attack was
successful or if changes were made to the security state of the system.

    Event outcomes can include indicators of event success or failure and
event-specific results (e.g., the security state of the information system
after the event occurred). As such, they also provide a means to measure the
impact of an event and help authorized personnel to determine the appropriate
response.
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
    -p <Password> --set --rbac-username jdoe --rbac-password @dminP@asswd2020 \
    --rbac-name \"John Doe\" --roles replication_admin \
    --auth-domain local
      
  Verify that the event logged contains the required fields:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log 
      
  If the log does not contain the \"name\" and \"description\" fields, 
  this is a finding.    
  "
  desc  "fix", "
  Enable session auditing on the Couchbase cluster to produce sufficient
  information regarding the outcome (success or failure) of the events.
  
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
  tag "gtitle": "SRG-APP-000099-DB-000043"
  tag "gid": "V-32373"
  tag "rid": "SV-42710r3_rule"
  tag "stig_id": "SRG-APP-000099-DB-000043"
  tag "fix_id": "F-36287r2_fix"
  tag "cci": ["CCI-000134"]
  tag "nist": ["AU-3", "Rev_4"]

  describe "Create the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username jdoe --rbac-password @dminP@asswd2020 --rbac-name 'John Doe' \
    --roles replication_admin --auth-domain local") }
    its('exit_status') { should eq 0 }
  end

  describe "The logged event should contain required fields. The" do
    subject { command("grep 'jdoe' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /"name"/}
    its('stdout') { should match /"description"/}
  end

  describe "Delete the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --delete --rbac-username jdoe --auth-domain local") }
    its('exit_status') { should eq 0 }
  end
end
