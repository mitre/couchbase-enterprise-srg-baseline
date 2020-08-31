# encoding: UTF-8

control "V-58083" do
  title "Couchbase must be able to generate audit records when security objects
are accessed."
  desc  "Changes to the security configuration must be tracked.

    This requirement applies to situations where security data is retrieved or
modified via data manipulation operations, as opposed to via specialized
security functionality.

    In an SQL environment, types of access include, but are not necessarily
limited to:
    SELECT
    INSERT
    UPDATE
    DELETE
    EXECUTE
  "
  desc  "rationale", ""
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
    Verify the events were logged with the following command:
      $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log
      Output:  {\"bucket_name\":\"test-data\",\"description\":\"Bucket was
created\",\"id\":8201,\"name\":\"create
bucket\",\"props\":{\"compression_mode\":\"passive\",\"conflict_resolution_type\":\"seqno\",\"durability_min_level\":\"none\",\"eviction_policy\":\"value_only\",\"flush_enabled\":false,\"max_ttl\":0,\"num_threads\":3,\"ram_quota\":268435456,\"replica_index\":true,\"storage_mode\":\"couchstore\"},\"real_use\"rid\"\":{\"domain\":\"local\",\"user\":\"jdoe\"},\"remote\":{\"ip\":\"127.0.0.1\",\"port\":45934},\"timestamp\":\"2020-08-20T20:30:34.115Z\",\"type\":\"membase\"}
    If the above steps cannot verify that audit records are produced when
security objects are accessed, this is a finding.

  "
  desc  "fix", "
    Enable session auditing on the Couchbase cluster to produce audit records
when security objects are accessed.
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
  tag "gtitle": "SRG-APP-000492-DB-000332"
  tag "gid": "V-58083"
  tag "rid": "SV-72513r1_rule"
  tag "stig_id": "SRG-APP-000492-DB-000332"
  tag "fix_id": "F-63291r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end
