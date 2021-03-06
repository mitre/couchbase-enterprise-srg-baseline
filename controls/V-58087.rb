# encoding: UTF-8

control "V-58087" do
  title "Couchbase must generate audit records when security objects are
  modified."

  desc  "Changes in the database objects (tables, views, procedures, functions)
  that record and control permissions, privileges, and roles granted to users and
  roles must be tracked. Without an audit trail, unauthorized changes to the
  security subsystem could go undetected. The database could be severely
  compromised or rendered inoperative."
  desc  "check", "
  If the Couchbase architecture makes it impossible for any user, even with
  the highest privileges, to directly view or directly modify the contents of its
  built-in security objects, and if there are no additional, locally-defined
  security objects in the database(s), this is not a finding.
    
  Couchbase auditing is capable of logging all reads, creations,
  modifications, and deletions.
    
  As the Full Admin, create a user account and grant the user the
  cluster_admin role by executing the following command:
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
    -p <Password> --set --rbac-username jdoe --rbac-password doe_cbP@ssw0rd2020 \\
    --rbac-name \"John Doe\" --roles cluster_admin \\
    --auth-domain local
  
  As the John Doe user, create a bucket in the cluster by executing the
  following command:
    $ couchbase-cli bucket-create -c <host>:<port> --username jdoe --password
    doe_cbP@ssw0rd2020 --bucket test-data --bucket-type couchbase --bucket-ramsize 200
    
  As the John Doe user, edit memory allocated for the bucket created by
  executing the following command:
    $ couchbase-cli bucket-edit -c <host>:<port> --username jdoe \\
    --password doe_cbP@ssw0rd2020  --bucket test-data --bucket-ramsize 100
  
  Verify the events were logged with the following command:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log
      Output:
      {\"bucket_name\":\"test-data\",\"description\":\"Bucket was
      modified\",\"id\":8202,\"name\":\"modify bucket\",\"props\"
      :{\"ram_quota\":104857600,\"storage_mode\":\"couchstore\"},
      \"real_use\"rid\"\":{\"domain\":\"local\",\"user\":\"jdoe\"},
      \"remote\":{\"ip\":\"127.0.0.1\",\"port\":46976},\"timestamp\"
      :\"2020-08-20T21:06:09.746Z\",\"type\":\"membase\"}
  If the above steps cannot verify that audit records are produced when
  security objects are modified, this is a finding."
  desc  "fix", "
  Enable session auditing on the Couchbase cluster to produce audit records
  when security objects are modified.
  Couchbase Server 6.5.0 and earlier -
    As the Full Admin, execute the following command to enable auditing:
      $ couchbase-cli setting-audit --cluster <host>:<port> --u <Full Admin>
      --password <Password> --audit-enabled 1 --audit-log-rotate-interval 604800
      --audit-log-path /opt/couchbase/var/lib/couchbase/logs
  Couchbase Server Version 6.5.1 and later -
    As the Full Admin, execute the following command to enable auditing:
      $ couchbase-cli setting-audit --cluster <host>:<port> --u <Full Admin>
      --password <Password> --set  --audit-enabled 1 --audit-log-rotate-interval
      604800 --audit-log-path /opt/couchbase/var/lib/couchbase/logs"

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000496-DB-000334"
  tag "gid": "V-58087"
  tag "rid": "SV-72517r1_rule"
  tag "stig_id": "SRG-APP-000496-DB-000334"
  tag "fix_id": "F-63295r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]

  describe "Create the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username jdoe --rbac-password doe_cbP@ssw0rd2020 \
    --rbac-name 'John Doe' --roles cluster_admin --auth-domain local") }
    its('exit_status') { should eq 0 }
  end

  describe "Create a Bucket as jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli bucket-create \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    --username jdoe --password doe_cbP@ssw0rd2020 \
    --bucket test-data --bucket-type couchbase --bucket-ramsize 200") }
    its('exit_status') { should eq 0 }
  end

  describe "Edit bucket as jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli bucket-edit \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} -u jdoe \
    -p doe_cbP@ssw0rd2020 --bucket test-data --bucket-ramsize 100") } 
    its('exit_status') { should eq 0 }
  end
  
  describe "The modify event should be logged. The" do
    subject { command("grep 'modify bucket' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /"jdoe"/}
  end

  describe "Delete the Bucket. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli bucket-delete \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    --username #{input('cb_full_admin')} --password #{input('cb_full_admin_password')} \
    --bucket test-data") }
    its('exit_status') { should eq 0 }
  end

  describe "Delete the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --delete --rbac-username jdoe --auth-domain local") }
    its('exit_status') { should eq 0 }
  end

end