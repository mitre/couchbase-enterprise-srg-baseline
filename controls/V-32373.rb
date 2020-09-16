# encoding: UTF-8

control "V-32373" do
  title "Couchbase must produce audit records containing sufficient information
to establish the outcome (success or failure) of the events."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without information about the outcome of events, security
personnel cannot make an accurate assessment as to whether an attack was
successful or if changes were made to the security state of the system.

    Event outcomes can include indicators of event success or failure and
event-specific results (e.g., the security state of the information system
after the event occurred). As such, they also provide a means to measure the
impact of an event and help authorized personnel to determine the appropriate
response.
  "
  desc  "check", "
  Once enabled on the cluster, Couchbase auditing provides the following
  fields by default:
    - \"id\" - ID of Event
    - \"name\" - Name of Event (can indicate success/failure)
    - \"description\" - Event Description (can indicate success/failure)
    - \"filtering_permitted\" - Whether the event is filterable
    - \"mandatory_fields\" - Includes \"timestamp\" (UTC time and ISO 8601
      format) and \"user\" fields
  Note that different event-types generate different field-subsets. Below are
  some of the fields provided:
    - \"node_id\" - ID of Node
    - \"session_id\" - ID of current Session
    - \"ip\" - Remote IP address
    - \"port\" - Remote port
    - \"bucket_name\" - Name of Bucket

  As the Full Admin, verify that auditing is enabled by executing the following command:

  $ curl -v -X GET -u <Full Admin>:<Password> http://<host>:<port>/settings/audit

  Verify from the output that \"auditEnabled\" is set to \"true\". If  \"auditEnabled\" 
  is not set to \"true\", this is finding.
  "
  desc  "fix", "
  Enable session auditing on the Couchbase cluster to produce sufficient
  information regarding the outcome (success or failure) of the events.
  
  Couchbase Server 6.5.0 and earlier -
  As the Full Admin, execute the following command to enable auditing:
    $ couchbase-cli setting-audit --cluster <host>:<port> --u <Full Admin>
  --password <Password> --audit-enabled 1 --audit-log-rotate-interval 604800
  --audit-log-path /opt/couchbase/var/lib/couchbase/logs

  Couchbase Server Version 6.51 and later -
  As the Full Admin, execute the following command to enable auditing:
    $ couchbase-cli setting-audit --cluster <host>:<port> --u <Full Admin>
    --password <Password> --set  --audit-enabled 1 --audit-log-rotate-interval
    604800 --audit-log-path /opt/couchbase/var/lib/couchbase/logs
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000099-DB-000043"
  tag "gid": "V-32373"
  tag "rid": "SV-42710r3_rule"
  tag "stig_id": "SRG-APP-000099-DB-000043"
  tag "fix_id": "F-36287r2_fix"
  tag "cci": ["CCI-000134"]
  tag "nist": ["AU-3", "Rev_4"]

  describe "Couchbase log auditing should be enabled." do
    subject { json( command: "curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
    http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/audit") }
    its('auditdEnabled') { should eq true }
  end 

end
