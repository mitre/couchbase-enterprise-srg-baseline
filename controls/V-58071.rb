# encoding: UTF-8

control "V-58071" do
  title "Couchbase must generate audit records when privileges/permissions are added."
  desc  "Changes in the permissions, privileges, and roles granted to users and
  roles must be tracked. Without an audit trail, unauthorized elevation or
  restriction of privileges could go undetected. Elevated privileges give users
  access to information and functionality that they should not have; restricted
  privileges wrongly deny access to authorized users.

  In an SQL environment, adding permissions is typically done via the GRANT
  command, or, in the negative, the DENY command."

  desc  "check", "
  Couchbase auditing is capable of logging all reads, creations,
  modifications, and deletions.
  First, as the Full Admin, create a user account by executing the following
  command:
    $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
    -p <Password> --set --rbac-username jdoe --rbac-password cbpass \\
    --rbac-name \"John Doe\" --roles replication_admin \\
    --auth-domain local
    
  Then, as the Full Admin, grant the John Doe user a new role:
    $couchbase-cli user-manage -c localhost:8091 -u admin -p password \
    --set --roles admin --rbac-username jdoe --auth-domain local

  If the above steps cannot verify that audit records are produced when 
  privileges/permissions/role memberships are added, this is a finding."

  desc  "fix", "
  Enable session auditing on the Couchbase cluster to produce audit records
  when privileges/permissions are added.
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
  Enable the required set of auditable events by doing the following:
    As the Full Admin, log into the cluster and use  the following documentation 
    to enable all on the \"Query and Index Services Event:
    - https://docs.couchbase.com/server/current/manage/manage-security/manage-auditing.html"

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000326"
  tag "gid": "V-58071"
  tag "rid": "SV-72501r2_rule"
  tag "stig_id": "SRG-APP-000495-DB-000326"
  tag "fix_id": "F-63277r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]

  describe "Add the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \ 
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username jdoe --rbac-password cbpass --rbac-name 'John Doe' \
    --roles replication_admin --auth-domain local") } 
    its('exit_status') { should eq 0 }
  end

  describe "Grant permissions to jdoe user. The" do 
    subject { command("cbq -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --engine=http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}
    --script='GRANT cluster_admin TO jdoe'")}
    its('exit_status') { should eq 0 }
  end

  describe "The logged event should contain required fields. The" do
    subject { command("grep 'A N1QL GRANT ROLE' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /"success"/}
  end

  describe "Delete the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --delete --rbac-username jdoe --auth-domain local") }
    its('exit_status') { should eq 0 }
  end
end
