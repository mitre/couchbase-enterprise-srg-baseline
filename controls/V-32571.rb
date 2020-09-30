# encoding: UTF-8

control "V-32571" do
  title "Couchbase must reveal detailed error messages only to the ISSO, ISSM,
SA and DBA."
  desc  "If Couchbase provides too much information in error logs and
administrative messages to the screen, this could lead to compromise. The
structure and content of error messages need to be carefully considered by the
organization and development team. The extent to which the information system
is able to identify and handle error conditions is guided by organizational
policy and operational requirements.

    Some default Couchbase error messages can contain information that could
aid an attacker in, among others things, identifying the database type, host
address, or state of the database. Custom errors may contain sensitive customer
information.

    It is important that detailed error messages be visible only to those who
are authorized to view them; that general users receive only generalized
acknowledgment that errors have occurred; and that these generalized messages
appear only when relevant to the user's task. For example, a message along the
lines of, \"An error has occurred. Unable to save your changes. If this problem
persists, please contact your help desk\" would be relevant. A message such as
\"Warning: your transaction generated a large number of page splits\" would
likely not be relevant.

    Administrative users authorized to review detailed error messages typically
are the ISSO, ISSM, SA, and DBA. Other individuals or roles may be specified
according to organization-specific needs, with appropriate approval.

    This calls for inspection of application source code, which will require
collaboration with the application developers. It is recognized that in many
cases, the database administrator (DBA) is organizationally separate from the
application developers, and may have limited, if any, access to source code.
Nevertheless, protections of this type are so important to the secure operation
of databases that they must not be ignored. At a minimum, the DBA must attempt
to obtain assurances from the development organization that this issue has been
addressed, and must document what has been discovered.
  "
  desc  "check", "
    Check Couchbase settings and custom database code to determine if detailed
error messages are ever displayed to unauthorized individuals.
    Review the ownership and permissions of the audit logs:
      $ ls \xE2\x80\x93ald /opt/couchbase/var/lib/couchbase/logs
    If the logs are not owned by both the \"couchbase\" user and group, this is
a finding. If the file permission are not 600, this is a finding.
  "
  desc  "fix", "
    As the root or sudo user, change the permissions/ownership of the logs
using the following commands:
      $ chown -R couchbase:couchbase /opt/couchbase/var/lib/couchbase/logs
      $ chmod 700 /opt/couchbase/var/lib/couchbase/logs
      $ chmod 600 /opt/couchbase/var/lib/couchbase/*.logs
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000267-DB-000163"
  tag "gid": "V-32571"
  tag "rid": "SV-42908r5_rule"
  tag "stig_id": "SRG-APP-000267-DB-000163"
  tag "fix_id": "F-36486r2_fix"
  tag "cci": ["CCI-001314"]
  tag "nist": ["SI-11 b", "Rev_4"]

  describe file(input('cb_static_conf')) do
    its('owner') { should be_in input('cb_service_user') }
    its('group') { should be_in input('cb_service_group') }
    it { should_not be_more_permissive_than('0600') }
    
  describe file(input('cb_audit_log')) do
    its('owner') { should be_in input('cb_service_user') }
    its('group') { should be_in input('cb_service_group') }
    it { should_not be_more_permissive_than('0600') }
  end
  end
end