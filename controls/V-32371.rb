# encoding: UTF-8

control "V-32371" do
  title "Couchbase must produce audit records containing sufficient information
to establish the sources (origins) of the events."
  desc  "Information system auditing capability is critical for accurate
forensic analysis. Without establishing the source of the event, it is
impossible to establish, correlate, and investigate the events relating to an
incident.

    In order to compile an accurate risk assessment and provide forensic
analysis, it is essential for security personnel to know where events occurred,
such as application components, modules, session identifiers, filenames, host
names, and functionality.

    In addition to logging where events occur within the application, the
application must also produce audit records that identify the application
itself as the source of the event.

    Associating information about the source of the event within the
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
  additional fields provided to establish what type of events occured. 
    - \"ip\" - Remote IP address
    - \"port\" - Remote port
    
  As the Full Admin, create a user account by executing the following command:
    $couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \
    -p <Password> --set --rbac-username jdoe --rbac-password doe_cbP@ssw0rd2020 \
    --rbac-name \"John Doe\" --roles replication_admin \
    --auth-domain local
    
  Verify that the event logged contains the required fields:
    $ cat <Couchbase Home>/var/lib/couchbase/logs/audit.log 
    
  If the log does not contain the \"ip\" and \"port\" fields,
  this is a finding.
  "
  desc  "fix", "
  Enable session auditing on the Couchbase cluster to produce sufficient
  information regarding the sources (origins) of the events.
  
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
  tag "gtitle": "SRG-APP-000098-DB-000042"
  tag "gid": "V-32371"
  tag "rid": "SV-42708r3_rule"
  tag "stig_id": "SRG-APP-000098-DB-000042"
  tag "fix_id": "F-36286r3_fix"
  tag "cci": ["CCI-000133"]
  tag "nist": ["AU-3", "Rev_4"]

  describe "Create the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --set --rbac-username jdoe --rbac-password doe_cbP@ssw0rd2020 --rbac-name 'John Doe' \
    --roles replication_admin --auth-domain local") }
    its('exit_status') { should eq 0 }
  end

  describe "The logged event should contain required fields. The" do
    subject { command("grep 'jdoe' #{input('cb_audit_log')} | tail -1") }
    its('stdout') { should match /"ip"/}
    its('stdout') { should match /"port"/}
  end

  describe "Delete the jdoe user. The" do 
    subject { command("#{input('cb_bin_dir')}/couchbase-cli user-manage \
    -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
    --delete --rbac-username jdoe --auth-domain local") }
    its('exit_status') { should eq 0 }
  end
end
