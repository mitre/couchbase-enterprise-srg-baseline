# encoding: UTF-8

control "V-58079" do
  title "Couchbase must generate audit records when privileges/permissions are
deleted."
  desc  "Changes in the permissions, privileges, and roles granted to users and
roles must be tracked. Without an audit trail, unauthorized elevation or
restriction of privileges could go undetected. Elevated privileges give users
access to information and functionality that they should not have; restricted
privileges wrongly deny access to authorized users.

    In an SQL environment, deleting permissions is typically done via the
REVOKE or DENY command.
  "
  desc  "check", "
    Couchbase auditing is capable of logging all reads, creations,
modifications, and deletions.
    As the Full Admin, create a user account and grant roles by running the
following command:
      $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
     -p <Password> --set --rbac-username jdoe --rbac-password cbpass \\
     --rbac-name \"John Doe\" --roles replication_admin,cluster_admin \\
     --auth-domain local
    As the Full Admin, revoke the \"cluster_admin\" role from John Doe:
      $ cbq -u <Full Admin> -p <Password> -engine=http://<host>:<port>/
--script=\"REVOKE cluster_admin FROM jdoe\"
    Verify the events were logged with the following command:
      $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log
      Output:
      {\"description\":\"A N1QL REVOKE ROLE statement was
executed\",\"id\":28686,\"isAdHoc\":true,\"metrics\":{\"elapsedTime\":\"104.68184ms\",\"executionTime\":\"104.610836ms\",\"resultCount\":0,\"resultSize\":0,\"warningCount\":1},\"name\":\"REVOKE
ROLE
statement\",\"node\":\"127.0.0.1:8091\",\"real_use\"rid\"\":{\"domain\":\"local\",\"user\":\"admin\"},\"remote\":{\"ip\":\"127.0.0.1\",\"port\":36832},\"requestId\":\"392e653c-644b-4907-8fbb-5bcb1be8298f\",\"statement\":\"REVOKE
cluster_admin FROM
jdoe;\",\"status\":\"success\",\"timestamp\":\"2020-08-21T15:54:42.820Z\",\"userAgent\":\"Go-http-client/1.1
(CBQ/2.0)\"}
    If the above steps cannot verify that audit records are produced when
privileges/permissions/role memberships are revoked, this is a finding.
  "
  desc  "fix", "
    Enable session auditing on the Couchbase cluster to produce audit records
when privileges/permissions are deleted.
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
  tag "gtitle": "SRG-APP-000499-DB-000330"
  tag "gid": "V-58079"
  tag "rid": "SV-72509r2_rule"
  tag "stig_id": "SRG-APP-000499-DB-000330"
  tag "fix_id": "F-63287r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end
