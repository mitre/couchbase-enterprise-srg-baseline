# encoding: UTF-8
control "V-58077" do
  desc  "rationale", ""
  desc  "check", "
    If there is no distinction in Couchbase's security architecture between
modifying permissions on the one hand, and adding and deleting permissions on
the other hand, this is not a finding.
    Couchbase auditing is capable of logging all reads, creations,
modifications, and deletions.
    First, as the Full Admin, create two user accounts by executing the
following commands:
      $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
     -p <Password> --set --rbac-username jdoe --rbac-password cbpass \\
     --rbac-name \"John Doe\" --roles replication_admin \\
     --auth-domain local
      $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
     -p <Password> --set --rbac-username janedoe --rbac-password cbpass \\
     --rbac-name \"Jane Doe\" --roles replication_admin \\
     --auth-domain local
    Then, as the John Doe user, grant the Jane Doe a new role:
      $ cbq -u jdoe -p cbpass -engine=http://<host>:<port>/ --script=\"GRANT
cluster_admin TO janedoe\"
    Verify the events were logged with the following command:
      $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log
      Output:
      {\"description\":\"A N1QL GRANT ROLE statement was
executed\",\"id\":28685,\"isAdHoc\":true,\"metrics\":{\"elapsedTime\":\"476.925\xC2\xB5s\",\"errorCount\":1,\"executionTime\":\"388.584\xC2\xB5s\",\"resultCount\":0,\"resultSize\":0},\"name\":\"GRANT
ROLE
statement\",\"node\":\"127.0.0.1:8091\",\"real_use\"rid\"\":{\"domain\":\"local\",\"user\":\"jdoe\"},\"remote\":{\"ip\":\"127.0.0.1\",\"port\":39960},\"requestId\":\"1e51a528-6108-44cd-a387-076502e61728\",\"statement\":\"GRANT
cluster_admin TO
janedoe;\",\"status\":\"fatal\",\"timestamp\":\"2020-08-21T17:23:55.427Z\",\"userAgent\":\"Go-http-client/1.1
(CBQ/2.0)\"}
    If the above steps cannot verify that audit records are produced when
privileges/permissions/role memberships are unsuccessfully added, this is a
finding.
  "
  desc  "fix", "
    Enable session auditing on the Couchbase cluster to produce audit records
when privileges/permissions are unsuccessfully modified.
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
      -
https://docs.couchbase.com/server/current/manage/manage-security/manage-auditing.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000329"
  tag "gid": "V-58077"
  tag "rid": "SV-72507r2_rule"
  tag "stig_id": "SRG-APP-000495-DB-000329"
  tag "fix_id": "F-63285r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end
