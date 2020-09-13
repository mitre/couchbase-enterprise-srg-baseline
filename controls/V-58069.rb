# encoding: UTF-8

control "V-58069" do
  title "Couchbase must be able to generate audit records when unsuccessful
attempts to retrieve privileges/permissions occur."
  desc  "Under some circumstances, it may be useful to monitor who/what is
reading privilege/permission/role information. Therefore, it must be possible
to configure auditing to do this. Couchbases typically make such information
available through views or functions.

    This requirement addresses explicit requests for privilege/permission/role
membership information. It does not refer to the implicit retrieval of
privileges/permissions/role memberships that Couchbase continually performs to
determine if any and every action on the database is permitted.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.
  "
  desc  "check", "
    Review Couchbase documentation to verify that audit records can be produced
when the system denies or fails to complete attempts to retrieve
privileges/permissions/role membership.
    If Couchbase is not capable of this, this is a finding.
    If Couchbase is currently required to audit the retrieval of
privilege/permission/role membership information, review Couchbase/database
security and audit configurations to verify that audit records are produced
when Couchbase denies retrieval of privileges/permissions/role memberships.
    If they are not produced, this is a finding.
    Review Couchbase/database security and audit configurations to verify that
audit records are produced when other errors prevent retrieval of
privileges/permissions/role memberships.
    If they are not produced, this is a finding.
  "
  desc  "fix", "
    Deploy a Couchbase capable of producing the required audit records when it
denies or fails to complete access to privileges/permissions/role membership.
    If currently required, configure Couchbase to produce audit records when it
denies access to privileges/permissions/role membership.
    Configure Couchbase to produce audit records when other errors prevent
access to privileges/permissions/role membership.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000091-DB-000325"
  tag "gid": "V-58069"
  tag "rid": "SV-72499r1_rule"
  tag "stig_id": "SRG-APP-000091-DB-000325"
  tag "fix_id": "F-63277r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  
  describe "This test requires a Manual Review: Review Couchbase documentation to verify that audit records can be produced
  when the system denies or fails to complete attempts to retrieve privileges/permissions/role membership." do
    skip "This test requires a Manual Review: Review Couchbase documentation to verify that audit records can be produced
    when the system denies or fails to complete attempts to retrieve privileges/permissions/role membership." 
  end
end
