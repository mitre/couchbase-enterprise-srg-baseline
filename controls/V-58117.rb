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
    CREATE
    ALTER
    DROP
    GRANT
    REVOKE
    DENY

    Note that it is particularly important to audit, and tightly control, any
action that weakens the implementation of this requirement itself, since the
objective is to have a complete audit trail of all administrative activity.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  "rationale", ""
  desc  "check", "
    When enabled on the cluster, Couchbase auditing configuration includes
certain privilege events by default. The Full Admin can specify functionality
that should be audited.
    Couchbase Server 6.5.0 and earlier -
      As root or a sudo user, verify that the \"audit.log\" file exists in the
var/lib/couchbase/logs directory of the Couchbase application home (example:
/opt/couchbase/var/lib/couchbase/logs) and is populated with data captured.
      Review the audit.log file. If it does not exist or not populated with
data captured, this is a finding.
    Couchbase Server Version 6.5.1 and later -
      As the Full Admin, verify that auditing is enabled by executing the
following command:
       $ couchbase-cli setting-audit -c <host>:<port> -u <Full Admin> -p
<Password> --get-settings
      Review the output of the command. If \"Audit enabled\" is not set to
\"true\", this is finding.
  "
  desc  "fix", "
    Enable session auditing on the Couchbase cluster to configure required
functionality to be audited.
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
  tag "gtitle": "SRG-APP-000504-DB-000355"
  tag "gid": "V-58117"
  tag "rid": "SV-72547r1_rule"
  tag "stig_id": "SRG-APP-000504-DB-000355"
  tag "fix_id": "F-63325r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end
