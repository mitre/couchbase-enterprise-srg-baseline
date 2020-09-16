# encoding: UTF-8

control "V-32362" do
  title "Couchbase must provide audit record generation capability for
  DoD-defined auditable events within all Couchbase/database components."
  desc  "Without the capability to generate audit records, it would be
  difficult to establish, correlate, and investigate the events relating to an
  incident or identify those responsible for one.

  Audit records can be generated from various components within Couchbase
  (e.g., process, module). Certain specific application functionalities may be
  audited as well. The list of audited events is the set of events for which
  audits are to be generated. This set of events is typically a subset of the
  list of all events for which the system is capable of generating audit records.

  DoD has defined the list of events for which Couchbase will provide an
  audit record generation capability as the following:

  (I) Successful and unsuccessful attempts to access, modify, or delete
  privileges, security objects, security levels, or categories of information
  (e.g., classification levels);

  (ii) Access actions, such as successful and unsuccessful logon attempts,
  privileged activities, or other system-level access, starting and ending time
  for user access to the system, concurrent logons from different workstations,
  successful and unsuccessful accesses to objects, all program initiations, and
  all direct access to the information system; and

  (iii) All account creation, modification, disabling, and termination
  actions.

  Organizations may define additional events requiring continuous or ad hoc
  auditing.
  "
  desc  "check", "
  Check Couchbase auditing to determine whether organization-defined
  auditable events are being audited by the system.
  To verify other events being audited do the following:
  
  Couchbase Server 6.5.0 and earlier - 
  As the Full Admin, execute the following command to verify which events are disabled:

    $ curl -v -X GET -u <Full Admin>:<Password> http://<host>:<port>/settings/audit

  Review the output. If organization-defined auditable events are not being audited, this is a finding.

  Couchbase Server Version 6.5.1 and later -
  When auditing is enabled, the following events are audited by default and
  cannot be turned off:
    - authentication failed
    - command access failed
    - privilege debug configured
    - privilege debug
      
  As the Full Admin, execute the following command to verify which events
  are disabled and which are enabled:
    $ couchbase-cli setting-audit -c <host>:<port> -u <Full Admin> -p
    <Password> --get-settings

  Review the output. If organization-defined auditable events are not being audited, this is a
  finding.
  "
  desc  "fix", "
  Deploy a Couchbase database that supports the DoD minimum set of auditable
  events.
    
  Enable the required set of auditable events by doing the following:
  
  Couchbase Server 6.5.0 and earlier -
  As the Full Admin, log into the cluster and use  the following
  documentation to enable required events:
    - https://docs.couchbase.com/server/6.0/manage/manage-security/manage-auditing.html
    - https://docs.couchbase.com/server/6.5/manage/manage-security/manage-auditing.html
  
  Couchbase Server 6.5.1 and later -
  As the Full Admin, log into the cluster and use the following
  documentation to enable required events:
    - https://docs.couchbase.com/server/6.5/manage/manage-security/manage-auditing.html
    - https://docs.couchbase.com/server/6.6/manage/manage-security/manage-auditing.html

  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000089-DB-000064"
  tag "gid": "V-32362"
  tag "rid": "SV-42699r3_rule"
  tag "stig_id": "SRG-APP-000089-DB-000064"
  tag "fix_id": "F-36277r2_fix"
  tag "cci": ["CCI-000169"]
  tag "nist": ["AU-12 a", "Rev_4"]

  if couchbase_version.include?("6.5.1") || couchbase_version.include?("6.6.0")
    input('cb_required_audit_events').each do |event_name|
      describe command("couchbase-cli setting-audit -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --get-settings | grep '#{event_name}'") do
        its('stdout') { should include "True" }
      end 
    end 
  else
    input('cb_required_audit_event_ids').each do |event_id|
      describe command("curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/audit") do
        its('stdout') { should_not include event_id }
      end 
    end
  end
end
