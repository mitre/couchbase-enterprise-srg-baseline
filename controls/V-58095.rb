# encoding: UTF-8

control "V-58095" do
  title "Couchbase must generate audit records when categories of information
  (e.g., classification levels/security levels) are accessed."
  desc  "Changes in categories of information must be tracked. Without an audit
  trail, unauthorized access to protected data could go undetected.

  For detailed information on categorizing information, refer to FIPS
  Publication 199, Standards for Security Categorization of Federal Information
  and Information Systems, and FIPS Publication 200, Minimum Security
  Requirements for Federal Information and Information Systems.
  "
  desc  "check", "
  When enabled on the cluster, Couchbase auditing is capable of logging all
  reads, creations, modifications, and deletions.
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
  tag "gtitle": "SRG-APP-000494-DB-000344"
  tag "gid": "V-58095"
  tag "rid": "SV-72525r1_rule"
  tag "stig_id": "SRG-APP-000494-DB-000344"
  tag "fix_id": "F-63303r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]

  describe "Couchbase log auditing should be enabled." do
    subject { json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
    http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/audit") }
      its('auditdEnabled') { should eq true }
      its('stdout') { should include 'timestamp' }
  end  
end
