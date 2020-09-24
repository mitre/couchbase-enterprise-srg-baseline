# encoding: UTF-8

control "V-58117" do
  title "Couchbase must generate audit records when unsuccessful attempts to
  execute privileged activities or other system-level access occur."
  desc  "Without tracking privileged activity, it would be difficult to
  establish, correlate, and investigate the events relating to an incident or
  identify those responsible for one.

  System documentation should include a definition of the functionality
  considered privileged.

  A privileged function in this context is any operation that modifies the
  structure of the database, its built-in logic, or its security settings. This
  would include all Data Definition Language (DDL) statements and all
  security-related statements. In an SQL environment, it encompasses, but is not
  necessarily limited to:
  - CREATE
  - ALTER
  - DROP
  - GRANT
  - REVOKE
  - DENY

  Note that it is particularly important to audit, and tightly control, any
  action that weakens the implementation of this requirement itself, since the
  objective is to have a complete audit trail of all administrative activity.

  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones.
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
    --rbac-name \"John Doe\" --roles ro_admin \
    --auth-domain local

  As the Jdoe user, try to create a user account by executing the following command:
    $couchbase-cli user-manage -c <host>:<port> -u jdoe \
    -p cbpass --set --rbac-username janedoe --rbac-password cbpass \
    --rbac-name \"Joane Doe\" --roles ro_admin \
    --auth-domain local
  
  Verify that unsuccessful attempts to create a user is auditted:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log 
      
  If the log does not contain the audit, this is a finding.  

  As the Jdoe user, try to delete a user account by executing the following command:
  $couchbase-cli user-manage -c <host>:<port> -u jdoe \
  -p cbpass --delete --rbac-username janedoe \
  --auth-domain local

  Verify that unsuccessful attempts to delete a user is auditted:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log 
      
  If the log does not contain the audit, this is a finding. 
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
  tag "gtitle": "SRG-APP-000504-DB-000355"
  tag "gid": "V-58117"
  tag "rid": "SV-72547r1_rule"
  tag "stig_id": "SRG-APP-000504-DB-000355"
  tag "fix_id": "F-63325r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]

  describe "Create the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username jdoe --rbac-password cbpass --rbac-name 'John Doe' \
    --roles ro_admin --auth-domain local") }
    its('exit_status') { should eq 0 }
  end  

  describe "As jdoe attempt to create the janedoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username janedoe --rbac-password cbpass --rbac-name 'Jane Doe' \
    --roles ro_admin --auth-domain local") }
    its('exit_status') { should eq 0 }
  end  

  describe "The logged event should contain record of failed user creation. The" do
    subject { command("grep 'jdoe' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /"unsuccessful attempt"/}
  end

  describe "As jdoe attempt to delete the janedoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --delete --rbac-username janedoe --auth-domain local") }
  end  

  describe "The logged event should contain record of failed user deletion. The" do
    subject { command("grep 'jdoe' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /"unsuccessful attempt"/}
  end

  describe "Delete the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --delete --rbac-username jdoe --auth-domain local") }
    its('exit_status') { should eq 0 }
  end
end
