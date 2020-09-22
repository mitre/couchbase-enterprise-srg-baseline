# encoding: UTF-8

control "V-32370" do
  title "Couchbase must produce audit records containing sufficient information
to establish where the events occurred."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without establishing where events occurred, it is impossible
to establish, correlate, and investigate the events relating to an incident.

    In order to compile an accurate risk assessment and provide forensic
analysis, it is essential for security personnel to know where events occurred,
such as application components, modules, session identifiers, filenames, host
names, and functionality.

    Associating information about where the event occurred within the
application provides a means of investigating an attack; recognizing resource
utilization or capacity thresholds; or identifying an improperly configured
application.
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
      
  Note that different event-types generate different field-subsets. Below are some 
  of the fields required to establish where the event occurred: 
    - \"sessionid\" - ID of current Session 
    - \"bucket_name\" - Name of Bucket
    
  As the Full Admin, create a bucket in the cluster by executing the following command:
    $ couchbase-cli bucket-create -c <host>:<port> --username <Full Admin>  --password <Password> 
    --bucket test-data --bucket-type couchbase --bucket-ramsize 100
  
  If the log does not contain the \"sessionid\" and \"bucket_name\" fields, this is a finding
  "
  desc  "fix", "
  Enable session auditing on the Couchbase cluster to produce sufficient
  information regarding where the events occurred. 
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
  tag "gtitle": "SRG-APP-000097-DB-000041"
  tag "gid": "V-32370"
  tag "rid": "SV-42707r3_rule"
  tag "stig_id": "SRG-APP-000097-DB-000041"
  tag "fix_id": "F-36285r3_fix"
  tag "cci": ["CCI-000132"]
  tag "nist": ["AU-3", "Rev_4"]

  describe "Create a Bucket. The" do 
    subject { command("couchbase-cli bucket-create -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    --username #{input('cb_full_admin')} --password #{input('cb_full_admin_password')} \
    --bucket test-data --bucket-type couchbase --bucket-ramsize 100") }
    its('exit_status') { should eq 0 }
  end

  describe "The logged event should contain required fields. The" do
    subject { command("grep 'test-data' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /"sessionid"/}
    its('stdout') { should match /"bucket_name"/}
  end

  describe "Delete the Bucket. The" do 
    subject { command("couchbase-cli bucket-delete -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    --username #{input('cb_full_admin')} --password #{input('cb_full_admin_password')} --bucket test-data") }
    its('exit_status') { should eq 0 }
  end
end
