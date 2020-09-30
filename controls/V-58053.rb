# encoding: UTF-8

control "V-58053" do
  title "Couchbase must allocate audit record storage capacity in accordance
with organization-defined audit record storage requirements."
  desc  "In order to ensure sufficient storage capacity for the audit logs,
Couchbase must be able to allocate audit record storage capacity. Although
another requirement (SRG-APP-000515-DB-000318) mandates that audit data be
off-loaded to a centralized log management system, it remains necessary to
provide space on the database server to serve as a buffer against outages and
capacity limits of the off-loading mechanism.

    The task of allocating audit record storage capacity is usually performed
during initial installation of Couchbase and is closely associated with the DBA
and system administrator roles. The DBA or system administrator will usually
coordinate the allocation of physical drive space with the application
owner/installer and the application will prompt the installer to provide the
capacity information, the physical location of the disk, or both.

    In determining the capacity requirements, consider such factors as: total
number of users; expected number of concurrent users during busy periods;
number and type of events being monitored; types and amounts of data being
captured; the frequency/speed with which audit records are off-loaded to the
central log management system; and any limitations that exist on Couchbase's
ability to reuse the space formerly occupied by off-loaded records.
  "
  desc  "check", "
    Investigate whether there have been any incidents where Couchbase ran out
of audit log space since the last time the space was allocated or other
corrective measures were taken.
    If there have been, this is a finding.
    Review the Couchbase audit settings:
    $ couchbase-cli setting-audit -c <host>:<port> --u <Full Admin> --p
<Password> --get-settings
    If audit-log-rotate-size is not greater than 0, this is a finding
  "
  desc  "fix", "
    Allocate sufficient audit file/table space to support peak demand.
    Configure Couchbase to rotate the log files based on organization defined
standards:
    $ couchbase-cli setting-audit -c <host>:<port> --u  <Full Admin> --p
<Password> --enabled 1 --audit-log-rotate-size <Size>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000357-DB-000316"
  tag "gid": "V-58053"
  tag "rid": "SV-72483r1_rule"
  tag "stig_id": "SRG-APP-000357-DB-000316"
  tag "fix_id": "F-63261r1_fix"
  tag "cci": ["CCI-001849"]
  tag "nist": ["AU-4", "Rev_4"]

  describe "Couchbase log auditing should be enabled." do
    subject { json( command("#{input('cb_bin_dir')}/couchbase-cli setting-audit -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
  --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --get-settings | grep 'Rotate size:'")) }
    its('stdout') { should be > 0 }
  end 
end
