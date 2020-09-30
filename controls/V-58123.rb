# encoding: UTF-8

control "V-58123" do
  title "Couchbase must generate audit records for all direct access to the
  database(s)."
  desc  "In this context, direct access is any query, command, or call to
  Couchbase that comes from any source other than the application(s) that it
  supports. Examples would be the command line or a database management utility
  program. The intent is to capture all activity from administrative and
  non-standard sources.
  "
  desc  "check", "
  As the Full Admin, create a user account by executing the following command:
    $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \
    -p <Password> --set --rbac-username jdoe --rbac-password @dminP@asswd2020 \
    --rbac-name \"John Doe\" --roles replication_admin \
    --auth-domain local

  Verify that the event logged contains a record of the user creation and the 
  source of the command.
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log 
      
  If the log does not contain the audit records, this is a finding.
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

  describe "Create the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username jdoe --rbac-password doe_cbP@ssw0rd2020 --rbac-name 'John Doe' \
    --roles replication_admin --auth-domain local") }
    its('exit_status') { should eq 0 }
  end

  describe "The logged event should contain record of user creation. The" do
    subject { command("grep 'jdoe' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /User was added/}
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
