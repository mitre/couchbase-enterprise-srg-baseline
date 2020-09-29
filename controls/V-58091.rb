# encoding: UTF-8

control "V-58091" do
  title "Couchbase must generate audit records when security objects are
  deleted."

  desc  "The removal of security objects from the database/Couchbase would
  seriously degrade a system's information assurance posture. If such an event
  occurs, it must be logged."
  desc  "check", "
  If the Couchbase architecture makes it impossible for any user, even with
  the highest privileges, to directly view or directly modify the contents of its
  built-in security objects, and if there are no additional, locally-defined
  security objects in the database(s), this is not a finding.
    
  Couchbase auditing is capable of logging all reads, creations,
  modifications, and deletions.
      
  As the Full Admin, create a user account and grant the user the
  cluster_admin role by executing the following command:
    $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
    -p <Password> --set --rbac-username jdoe --rbac-password cbpass \\
    --rbac-name \"John Doe\" --roles cluster_admin \\
    --auth-domain local
  
  As the John Doe user, create a bucket in the cluster by executing the
  following command:
    $ couchbase-cli bucket-create -c <host>:<port> --username jdoe --password
    cbpass --bucket test-data --bucket-type couchbase  --bucket-ramsize 256
      
  As the John Doe user, delete the bucket created by executing the following
  command:
    $ couchbase-cli bucket-delete -c <host>:<port> --username jdoe --password
    cbpass --bucket test-data
  Verify the events were logged with the following command:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log
      Output:
      {\"bucket_name\":\"test-data\",\"description\":\"Bucket was
      deleted\",\"id\":8203,\"name\":\"delete bucket\",\"real_use\"
      rid\"\":{\"domain\":\"local\",\"user\":\"jdoe\"},\"remote\":
      {\"ip\":\"127.0.0.1\",\"port\":47336},\"timestamp\":
      \"2020-08-20T21:17:06.409Z\"}
      
  If the above steps cannot verify that audit records are produced when
  security objects are deleted, this is a finding."

  desc  "fix", "
  Enable session auditing on the Couchbase cluster to produce audit records
  when security objects are delete.
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
  tag "gtitle": "SRG-APP-000501-DB-000336"
  tag "gid": "V-58091"
  tag "rid": "SV-72521r1_rule"
  tag "stig_id": "SRG-APP-000501-DB-000336"
  tag "fix_id": "F-63299r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]


  describe "Create bucket. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli bucket-create \ 
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --bucket test-data --bucket-type couchbase  --bucket-ramsize 256") } 
    its('exit_status') { should eq 0 }
  end

  describe "Delete bucket. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli bucket-delete \ 
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --bucket test-data") } 
    its('exit_status') { should eq 0 }
  end

  describe "The logged event should contain required fields. The" do
    subject { command("grep 'bucket' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match "deleted"}
  end
end

