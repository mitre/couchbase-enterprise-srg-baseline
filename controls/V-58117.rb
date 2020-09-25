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
  First, as the Full Admin, create two user accounts by executing the following commands:
    $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \
    -p <Password> --set --rbac-username jdoe --rbac-password @dminP@asswd2020 \
    --rbac-name \"John Doe\" --roles data_reader[*] \
    --auth-domain local

    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \
    -p <Password> --set --rbac-username janedoe --rbac-password cbpass \
    --rbac-name \"Jane Doe\" --roles replication_admin \
    --auth-domain local
  
  Then, as the John Doe, grant the Jane Doe user a new role:
    $ cbq -u jdoe -p cbpass -engine=http://<host>:<port>/ --script=\"GRANT cluster_admin TO janedoe\"
  
  Verify the unsuccessful attempt to assign a role is auditted:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log 
      
  If the audit log does not include the event, this is a finding.
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
    --set --rbac-username jdoe --rbac-password doe_cbP@ssw0rd2020 --rbac-name 'John Doe' \
    --roles data_reader[*] --auth-domain local") }
    its('exit_status') { should eq 0 }
  end

  describe "Create the janedoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username janedoe --rbac-password doe_cbP@ssw0rd2020 --rbac-name 'Jane Doe' \
    --roles replication_admin --auth-domain local") }
    its('exit_status') { should eq 0 }
  end

  describe "As jdoe attempt to change the role of the janedoe user. The" do 
    subject { command("cbq -u jdoe -p doe_cbP@ssw0rd2020 \
    --engine=http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    --script='GRANT cluster_admin TO janedoe'") }
    its('exit_status') { should eq 1 }
  end  

  describe "The logged event should contain record of failed user deletion. The" do
    subject { command("grep 'A N1QL GRANT ROLE' #{input('cb_audit_log')} | tail -1") }
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
