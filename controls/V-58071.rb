# encoding: UTF-8
control "V-58071" do
  desc  "rationale", ""
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
      $ cbq -u <Full Admin> -p <Password> -engine=http://<host>:<port>/
--script=\"GRANT cluster_admin TO jdoe\"
    Verify the events were logged with the following command:
      $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log
      Output:
      {\"description\":\"A N1QL GRANT ROLE statement was
executed\",\"id\":28685,\"isAdHoc\":true,\"metrics\":{\"elapsedTime\":\"163.459219ms\",\"executionTime\":\"163.397491ms\",\"resultCount\":0,\"resultSize\":0},\"name\":\"GRANT
ROLE
statement\",\"node\":\"127.0.0.1:8091\",\"real_use"rid"\":{\"domain\":\"local\",\"user\":\"admin\"},\"remote\":{\"ip\":\"127.0.0.1\",\"port\":38110},\"requestId\":\"a3344468-e5a2-44ba-af49-0fd858f20f7b\",\"statement\":\"GRANT
cluster_admin TO
jdoe;;\",\"status\":\"success\",\"timestamp\":\"2020-08-21T16:37:40.312Z\",\"userAgent\":\"Go-http-client/1.1
(CBQ/2.0)\"}
    If the above steps cannot verify that audit records are produced when
privileges/permissions/role memberships are added, this is a finding.
  "
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
      As the Full Admin, log into the cluster and use  the following
documentation to enable all on the "Query and Index Services Event:
      -
https://docs.couchbase.com/server/current/manage/manage-security/manage-auditing.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000495-DB-000326"
  tag "gid": "V-58071"
  tag "rid": "SV-72501r2_rule"
  tag "stig_id": "SRG-APP-000495-DB-000326"
  tag "fix_id": "F-63277r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end
