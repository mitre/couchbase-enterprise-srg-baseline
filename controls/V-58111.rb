# encoding: UTF-8

control "V-58111" do
  title "Couchbase must generate audit records showing starting and ending time
  for user access to the database(s)."
  desc  "For completeness of forensic analysis, it is necessary to know how
  long a user's (or other principal's) connection to Couchbase lasts. This can be
  achieved by recording disconnections, in addition to logons/connections, in the
  audit logs.

      Disconnection may be initiated by the user or forced by the system (as in a
  timeout) or result from a system or network failure. To the greatest extent
  possible, all disconnections must be logged.
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
  tag "gtitle": "SRG-APP-000505-DB-000352"
  tag "gid": "V-58111"
  tag "rid": "SV-72541r1_rule"
  tag "stig_id": "SRG-APP-000505-DB-000352"
  tag "fix_id": "F-63319r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]

  couchbase_version = command('couchbase-server -v').stdout

  if couchbase_version.include?("6.5.1") || couchbase_version.include?("6.6.0")
    describe json({ command "couchbase-cli setting-audit -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --get-settings"} ) do
      its('Audit enabled') { should eq 'true' }
    end
  else
    describe command("cat #{input('cb_audit_log')}") do
      its('stdout') { should include 'timestamp' }
    end
  end 
end
