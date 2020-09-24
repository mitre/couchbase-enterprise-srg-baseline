# encoding: UTF-8

control "V-32374" do
  title "Couchbase must produce audit records containing sufficient information
  to establish the identity of any user/subject or process associated with the
  event."
  desc  "Information system auditing capability is critical for accurate
  forensic analysis. Without information that establishes the identity of the
  subjects (i.e., users or processes acting on behalf of users) associated with
  the events, security personnel cannot determine responsibility for the
  potentially harmful event.

  Identifiers (if authenticated or otherwise known) include, but are not
  limited to, user database tables, primary key values, user names, or process
  identifiers.
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
    -p <Password> --set --rbac-username jdoe --rbac-password doe_cbP@ssw0rd2020 \
    --rbac-name \"John Doe\" --roles replication_admin \
    --auth-domain local
      
  Verify that the event logged contains the required fields:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log 
    
  If the log does not contain the \"real_userid\" field,
  this is a finding.
  "
  desc  "fix", "
  Enable session auditing on the Couchbase cluster to produce sufficient
  information regarding the user/subject or process associated with the event.
  
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
  tag "gtitle": "SRG-APP-000100-DB-000201"
  tag "gid": "V-32374"
  tag "rid": "SV-42711r3_rule"
  tag "stig_id": "SRG-APP-000100-DB-000201"
  tag "fix_id": "F-36288r3_fix"
  tag "cci": ["CCI-001487"]
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
