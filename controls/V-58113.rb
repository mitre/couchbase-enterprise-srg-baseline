# encoding: UTF-8

control "V-58113" do
  title "Couchbase must generate audit records when concurrent
  logons/connections by the same user from different workstations occur."
  desc  "For completeness of forensic analysis, it is necessary to track who
  logs on to Couchbase.

  Concurrent connections by the same user from multiple workstations may be
  valid use of the system; or such connections may be due to improper
  circumvention of the requirement to use the CAC for authentication; or they may
  indicate unauthorized account sharing; or they may be because an account has
  been compromised.

  (If the fact of multiple, concurrent logons by a given user can be reliably
  reconstructed from the log entries for other events (logons/connections;
  voluntary and involuntary disconnections), then it is not mandatory to create
  additional log entries specifically for this.)
  "
  desc  "check", "
  When enabled on the cluster, Couchbase auditing is capable of logging
  logins and logouts with timestamps by default.
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
  Enable session auditing on the Couchbase cluster to produce audit records
  when logins and logouts occur.
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
  tag "gtitle": "SRG-APP-000506-DB-000353"
  tag "gid": "V-58113"
  tag "rid": "SV-72543r1_rule"
  tag "stig_id": "SRG-APP-000506-DB-000353"
  tag "fix_id": "F-63321r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]

  describe "Couchbase log auditing should be enabled." do
    subject { json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
    http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/audit") }
      its('auditdEnabled') { should eq true }
  end
end
