# encoding: UTF-8

control "V-58095" do
  title "Couchbase must generate audit records when categories of information
  (e.g., classification levels/security levels) are accessed."
  desc  "Changes in categories of information must be tracked. Without an audit
  trail, unauthorized access to protected data could go undetected.

  For detailed information on categorizing information, refer to FIPS
  Publication 199, Standards for Security Categorization of Federal Information
  and Information Systems, and FIPS Publication 200, Minimum Security
  Requirements for Federal Information and Information Systems.
  "
  desc  "check", "
  Review the Couchbase documentation to verify that audit records can be produced when 
  categories of information are accessed, to include reads, creations, 
  modifications, and deletions.

  If Couchbase is not capable of this, this is a finding.
  
  Review Couchbase security and audit configurations to verify that audit 
  records are produced when categories of information are accessed, to include reads, 
  creations, modifications, and deletions.
  
  If they are not produced, this is a finding.
  "
  desc  "fix", "
  Deploy a Couchbase database capable of producing the required audit records 
  when categories of information are accessed.

  Configure the Couchbase database to produce audit records when categories 
  of information are accessed, to include reads, creations, modifications, and deletions.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000494-DB-000344"
  tag "gid": "V-58095"
  tag "rid": "SV-72525r1_rule"
  tag "stig_id": "SRG-APP-000494-DB-000344"
  tag "fix_id": "F-63303r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]

  describe "Couchbase is not currently capable of differentiating between catergories of information." do
   subject { input('cb_audit_categories_of_information') }
   it { should eq 'true'}
  end
end
