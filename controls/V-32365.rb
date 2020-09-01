# encoding: UTF-8

control "V-32365" do
  title "Couchbase must initiate session auditing upon startup."
  desc  "Session auditing is for use when a user's activities are under
investigation. To be sure of capturing all activity during those periods when
session auditing is in use, it needs to be in operation for the whole time
Couchbase is running."
  desc  "check", "
    Once enabled on the cluster, Couchbase will initiate session auditing upon
startup.
    Couchbase Server 6.5.0 and earlier -
      As root or a sudo user, verify that the \"audit.log\" file exists in the
var/lib/couchbase/logs directory of the Couchbase application home (example:
/opt/couchbase/var/lib/couchbase/logs) and is populated with data captured.
      Review the audit.log file. If it does not exist or not populated with
data captured, this is a finding.
    Couchbase Server Version 6.5.1 and later -
      As the Full Admin, verify that auditing is enabled by executing the
following command:
       $ couchbase-cli setting-audit -c <localhost>:<port> -u <Full Admin> -p
<Password> --get-settings
      Review the output of the command. If \"Audit enabled\" is not set to
\"True\", this is finding.
  "
  desc  "fix", "
    Enable session auditing on the Couchbase cluster.
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
  tag "gtitle": "SRG-APP-000092-DB-000208"
  tag "gid": "V-32365"
  tag "rid": "SV-42702r2_rule"
  tag "stig_id": "SRG-APP-000092-DB-000208"
  tag "fix_id": "F-36280r3_fix"
  tag "cci": ["CCI-001464"]
  tag "nist": ["AU-14 (1)", "Rev_4"]

  couchbase_version = command('couchbase-server -v').stdout

  if couchbase_version.include?("6.5.1") || couchbase_version.include?("6.6.0")
    describe command("couchbase-cli setting-audit -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --get-settings | grep 'Audit enabled:'") do
      its('stdout') { should include "True" }
    end 
  else
    describe file(input('cb_audit_log')) do
      it {should exist}
    end
  end
end
