# encoding: UTF-8

control "V-32347" do
  title "Couchbase must protect against a user falsely repudiating having
  performed organization-defined actions."
  desc  "Non-repudiation of actions taken is required in order to maintain data
  integrity. Examples of particular actions taken by individuals include creating
  information, sending a message, approving information (e.g., indicating
  concurrence or signing a contract), and receiving a message.

  Non-repudiation protects against later claims by a user of not having
  created, modified, or deleted a particular data item or collection of data in
  the database.

  In designing a database, the organization must define the types of data and
  the user actions that must be protected from repudiation. The implementation
  must then include building audit features into the application data tables and
  configuring Couchbase's audit tools to capture the necessary audit trail.
  Design and implementation also must ensure that applications pass individual
  user identification to Couchbase, even where the application connects to
  Couchbase with a standard, shared account.
  "
  desc  "check", "
  Review system documentation to determine the data and the actions on data
  that need to be protected from repudiation by means of audit trails.
  When enabled, Couchbase can identify a unique user for each record.

  Couchbase Server 6.5.0 and earlier -
  As the Full Admin, verify that auditing is enabled by executing the following command:

  $ curl -v -X GET -u <Full Admin>:<Password> http://<host>:<port>/settings/audit

  Verify from the output that \"auditEnabled\" is set to \"true\". If  \"auditEnabled\" 
  is not set to \"true\", this is finding.

  Couchbase Server Version 6.5.1 and later -
  As the Full Admin, verify that auditing is enabled by executing the
  following command:
    $ couchbase-cli setting-audit -c <host>:<port> -u <Full Admin> -p
    <Password> --get-settings
  Verify from the output that \"Audit enabled\" is set to \"True\". If
  \"Audit enabled\" is not set to true, this is finding."

  desc  "fix", "
  Use accounts assigned to individual users. Where the application connects
  to Couchbase using a standard, shared account, ensure that it also captures the
  individual user identification and passes it to Couchbase.
  
  Couchbase Server 6.5.0 and earlier -
  As the Full Admin, execute the following command to enable auditing:
    $ couchbase-cli setting-audit --cluster <host>:<port> --u <Full Admin>
   --password <Password> --audit-enabled 1 --audit-log-rotate-interval 604800
   --audit-log-path /opt/couchbase/var/lib/couchbase/logs
  
  Couchbase Server Version 6.51 and later -
  As the Full Admin, execute the following command to enable auditing:
    $ couchbase-cli setting-audit --cluster <host>:<port> --u <Full Admin>
    --password <Password> --set  --audit-enabled 1 --audit-log-rotate-interval
    604800 --audit-log-path /opt/couchbase/var/lib/couchbase/logs"

  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000080-DB-000063"
  tag "gid": "V-32347"
  tag "rid": "SV-42684r4_rule"
  tag "stig_id": "SRG-APP-000080-DB-000063"
  tag "fix_id": "F-36261r3_fix"
  tag "cci": ["CCI-000166"]
  tag "nist": ["AU-10", "Rev_4"]

  couchbase_version = command('couchbase-server -v').stdout

  if couchbase_version.include?("6.5.1") || couchbase_version.include?("6.6.0")
    describe command("couchbase-cli setting-audit -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --get-settings | grep 'Audit enabled:'") do
      its('stdout') { should include "True" }
    end 
  else
    describe json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/audit") do
      its('auditdEnabled') { should eq true }
    end 
  end
end
