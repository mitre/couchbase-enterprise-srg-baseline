# encoding: UTF-8

control "V-58061" do
  title "Couchbase must be configurable to overwrite audit log records, oldest
  first (First-In-First-Out - FIFO), in the event of unavailability of space for
  more audit log records."
  
  desc  "It is critical that when Couchbase is at risk of failing to process
  audit logs as required, it take action to mitigate the failure. Audit
  processing failures include: software/hardware errors; failures in the audit
  capturing mechanisms; and audit storage capacity being reached or exceeded.
  Responses to audit failure depend upon the nature of the failure mode.

  When availability is an overriding concern, approved actions in response to
  an audit failure are as follows:

  (i) If the failure was caused by the lack of audit record storage capacity,
  Couchbase must continue generating audit records, if possible (automatically
  restarting the audit service if necessary), overwriting the oldest audit
  records in a first-in-first-out manner.

  (ii) If audit records are sent to a centralized collection server and
  communication with this server is lost or the server fails, Couchbase must
  queue audit records locally until communication is restored or until the audit
  records are retrieved manually. Upon restoration of the connection to the
  centralized collection server, action should be taken to synchronize the local
  audit data with the collection server.

  Systems where availability is paramount will most likely be MAC I; the
  final determination is the prerogative of the application owner, subject to
  Authorizing Official concurrence. In any case, sufficient auditing resources
  must be allocated to avoid audit data loss in all but the most extreme
  situations."

  desc  "check", "
  Review system documentation to determine the data and the actions on data
  that need to be protected from repudiation by means of audit trails.
  When enabled, Couchbase can identify a unique user for each record.
  As the Full Admin, verify that auditing is enabled by executing the following command:
  $ curl -v -X GET -u <Full Admin>:<Password> http://<host>:<port>/settings/audit
  Verify from the output that \"auditEnabled\" is set to \"true\". If  \"auditEnabled\" 
  is not set to \"true\", this is finding."

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
      604800 --audit-log-path /opt/couchbase/var/lib/couchbase/logs"
      
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000109-DB-000321"
  tag "gid": "V-58061"
  tag "rid": "SV-72491r1_rule"
  tag "stig_id": "SRG-APP-000109-DB-000321"
  tag "fix_id": "F-63269r1_fix"
  tag "cci": ["CCI-000140"]
  tag "nist": ["AU-5 b", "Rev_4"]
  
  describe "Couchbase log auditing should be enabled." do
    subject { json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
    http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/audit") }
    its('auditdEnabled') { should eq true }
  end 
end
