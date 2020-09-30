# encoding: UTF-8

control "V-58081" do
  title "Couchbase must generate audit records when unsuccessful attempts to
  delete privileges/permissions occur."
  desc  "Failed attempts to change the permissions, privileges, and roles
  granted to users and roles must be tracked. Without an audit trail,
  unauthorized attempts to elevate or restrict privileges could go undetected.

  In an SQL environment, deleting permissions is typically done via the
  REVOKE or DENY command.

  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones."

  desc  "check", "
  Couchbase auditing is capable of logging all reads, creations,
  modifications, and deletions.

  First, as the Full Admin, create two user accounts by executing the
  following commands:
    $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
    -p <Password> --set --rbac-username jdoe --rbac-password doe_cbP@ssw0rd2020\\
    --rbac-name \"John Doe\" --roles replication_admin \\
    --auth-domain local
    $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
    -p <Password> --set --rbac-username janedoe --rbac-password doe_cbP@ssw0rd2020 \\
    --rbac-name \"Jane Doe\" --roles replication_admin,cluster_admin \\
    --auth-domain local

  Then, as the John Doe user, revoke the \"cluster_admin\" role from Jane Doe:
    $ cbq -u jdoe -p cbpass -engine=http://<host>:<port>/ --script=\"REVOKE
    cluster_admin FROM janedoe\"

  Verify the events were logged with the following command:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log
      Output:
      {\"description\":\"A N1QL REVOKE ROLE statement was executed\",\"id\":28686,
      \"isAdHoc\":true,\"metrics\":{\"elapsedTime\":\"12.61108ms\",\"errorCount\":1,
      \"executionTime\":\"12.55615ms\",\"resultCount\":0,\"resultSize\":0},\"name\":\"REVOKE
      ROLE statement\",\"node\":\"127.0.0.1:8091\",\"real_use\"rid\"\":{\"domain\":\"local\",
      \"user\":\"jdoe\"},\"remote\":{\"ip\":\"127.0.0.1\",\"port\":41172},\"requestId\":
      \"aa6cd9c6-b966-403c-aed2-0a3a86144602\",\"statement\":\"REVOKE cluster_admin FROM
      janedoe;\",\"status\":\"fatal\",\"timestamp\":\"2020-08-21T17:53:34.166Z\",\"userAgent\":
      \"Go-http-client/1.1 (CBQ/2.0)\"}

  If the above steps cannot verify that audit records are produced when
  privileges/permissions/role memberships are unsuccessfully revoked, this is a
  finding."
  
  desc  "fix", "
  Enable session auditing on the Couchbase cluster to produce audit records
  when privileges/permissions are unsuccessfully deleted.
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
  As the Full Admin, log into the cluster and use  the following
  documentation to enable all on the \"Query and Index Services Event:
    - https://docs.couchbase.com/server/current/manage/manage-security/manage-auditing.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000499-DB-000331"
  tag "gid": "V-58081"
  tag "rid": "SV-72511r2_rule"
  tag "stig_id": "SRG-APP-000499-DB-000331"
  tag "fix_id": "F-63289r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]

  describe "Add the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \ 
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username jdoe --rbac-password @dminP@asswd2020 --rbac-name 'John Doe' \
    --roles replication_admin --auth-domain local") } 
    its('exit_status') { should eq 0 }
  end

  describe "Add the janedoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \ 
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username janedoe --rbac-password @dminP@asswd2020 --rbac-name 'Jane Doe' \
    --roles replication_admin --auth-domain local") } 
    its('exit_status') { should eq 0 }
  end

  describe "Revoke permissions from janedoe by jdoe. The" do 
    subject { command("#{input('cb_bin_dir')}/cbq -u jdoe -p @dminP@asswd2020 --engine=http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}\
    --script='REVOKE replication_admin FROM janedoe'")}
    its('exit_status') { should eq 0 }
  end

  describe "The logged event should contain required fields. The" do
    subject { command("grep 'A N1QL REVOKE ROLE' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /"fatal"/}
  end

  describe "Delete the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --delete --rbac-username jdoe --auth-domain local") }
    its('exit_status') { should eq 0 }
  end

  describe "Delete the janedoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --delete --rbac-username janedoe --auth-domain local") }
    its('exit_status') { should eq 0 }
  end
end
