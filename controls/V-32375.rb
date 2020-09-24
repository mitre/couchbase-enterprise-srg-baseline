# encoding: UTF-8

control "V-32375" do
  title "Couchbase must include additional, more detailed, organization-defined
  information in the audit records for audit events identified by type, location,
  or subject."
  desc  "Information system auditing capability is critical for accurate
  forensic analysis. Reconstruction of harmful events or forensic analysis is not
  possible if audit records do not contain enough information. To support
  analysis, some types of events will need information to be logged that exceeds
  the basic requirements of event type, time stamps, location, source, outcome,
  and user identity. If additional information is not available, it could
  negatively impact forensic investigations into user actions or other malicious
  events.

  The organization must determine what additional information is required for
  complete analysis of the audited events. The additional information required is
  dependent on the type of information (e.g., sensitivity of the data and the
  environment within which it resides). At a minimum, the organization must
  employ either full-text recording of privileged commands or the individual
  identities of users of shared accounts, or both. The organization must maintain
  audit trails in sufficient detail to reconstruct events to determine the cause
  and impact of compromise.

  Examples of detailed information the organization may require in audit
  records are full-text recording of privileged commands or the individual
  identities of shared account users.
  "
  desc  "check", "
  Review the system documentation to identify what additional information the
  organization has determined to be necessary.

  Check Couchbase settings and existing audit records to verify that all
  organization-defined additional, more detailed information is in the audit
  records for audit events identified by type, location, or subject.
    
  If any additional information is defined and is not contained in the audit
  records, this is a finding.
  "
  desc  "fix", "Configure Couchbase audit settings to include all
  organization-defined detailed information in the audit records for audit events
  identified by type, location, or subject."
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000101-DB-000044"
  tag "gid": "V-32375"
  tag "rid": "SV-42712r4_rule"
  tag "stig_id": "SRG-APP-000101-DB-000044"
  tag "fix_id": "F-36289r3_fix"
  tag "cci": ["CCI-000135"]
  tag "nist": ["AU-3 (1)", "Rev_4"]

  couchbase_version = command('couchbase-server -v | egrep -o "([0-9]{1,}\.)+[0-9]{1,}"').stdout.strip

  if couchbase_version >= '6.5.1'
    input('cb_required_audit_events').each do |event_name|
      describe "The #{event_name} event should be enabled. The" do
        subject { command("#{input('cb_bin_dir')}/couchbase-cli setting-audit -u #{input('cb_full_admin')} \
        -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
        --get-settings | grep '#{event_name}'") }
        its('stdout') { should include "True" }
      end 
    end 
  else
    input('cb_required_audit_event_ids').each do |event_id|
      describe "The #{event_id} event id should not be disabled. The" do
        subject { command("curl -v -X GET -u #{input('cb_full_admin')}:#{input('cb_full_admin_password')} \
        http://#{input('cb_cluster_host')}:#{input('cb_cluster_port')}/settings/audit") }
        its('stdout') { should_not include event_id }
      end 
    end
  end
end
