# encoding: UTF-8

control "V-58093" do
  title "Couchbase must generate audit records when unsuccessful attempts to
  delete security objects occur."
  desc  "The removal of security objects from the database/Couchbase would
  seriously degrade a system's information assurance posture. If such an action
  is attempted, it must be logged.

  To aid in diagnosis, it is necessary to keep track of failed attempts in
  addition to the successful ones.
  "
  desc  "check", "
  If the Couchbase architecture makes it impossible for any user, even with
  the highest privileges, to directly view or directly modify the contents of its
  built-in security objects, and if there are no additional, locally-defined
  security objects in the database(s), this is not a finding.
      
  Review Couchbase documentation to verify that audit records can be produced
  when the system denies or fails to complete attempts to drop security objects.
  If Couchbase is not capable of this, this is a finding.
      
  Review Couchbase security and audit configurations to verify that audit
  records are produced when the system denies attempts to drop security objects.
  If they are not produced, this is a finding.
      
  Review Couchbase security and audit configurations to verify that audit
  records are produced when other errors prevent attempts to drop security
  objects.
  If they are not produced, this is a finding.
  "
  desc  "fix", "
  Deploy Couchbase database capable of producing the required audit records
  when it denies or fails to complete attempts to delete security objects.
      
  Configure Couchbase to produce audit records when it denies attempts to
  delete security objects.
      
  Configure Couchbase to produce audit records when other errors prevent
  attempts to delete security objects.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000501-DB-000337"
  tag "gid": "V-58093"
  tag "rid": "SV-72523r1_rule"
  tag "stig_id": "SRG-APP-000501-DB-000337"
  tag "fix_id": "F-63301r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
  
  describe "Couchbase is not currently capable of generating audit records when unsuccessful attempts to \
  delete security objects occur." do
    subject{ input('cb_audit_categories_of_information')}
    it { should eq 'true'}
  end
end
