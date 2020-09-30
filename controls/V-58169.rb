# encoding: UTF-8

control "V-58169" do
  title "Couchbase must implement cryptographic mechanisms to prevent
  unauthorized modification of organization-defined information at rest (to
  include, at a minimum, PII and classified information) on organization-defined
  information system components."
  desc  "Couchbases handling data requiring \"data at rest\" protections must
  employ cryptographic mechanisms to prevent unauthorized disclosure and
  modification of the information at rest. These cryptographic mechanisms may be
  native to Couchbase or implemented via additional software or operating
  system/file system settings, as appropriate to the situation.

  Selection of a cryptographic mechanism is based on the need to protect the
  integrity of organizational information. The strength of the mechanism is
  commensurate with the security category and/or classification of the
  information. Organizations have the flexibility to either encrypt all
  information on storage devices (i.e., full disk encryption) or encrypt specific
  data structures (e.g., files, records, or fields).

  The decision whether and what to encrypt rests with the data owner and is
  also influenced by the physical measures taken to secure the equipment and
  media on which the information resides.
  "
  desc  "check", "
  Review the system documentation to determine whether the organization has
  defined the information at rest that is to be protected from modification,
  which must include, at a minimum, PII and classified information.

  If no information is identified as requiring such protection, this is not a
  finding.
  
  If any of the information defined as requiring cryptographic protection
  from modification is not encrypted in a manner that provides the required level
  of protection, this is a finding.
  
  If an encryption at rest is required but the encryption tool is not installed 
  on the server, this is a finding.
  "
  desc  "fix", "
  Configure Couchbase settings to enable protections against
  man-in-the-middle attacks that guess at session identifier values.
  
  Review documentation to set up 3rd party encryption tools.
  https://docs.couchbase.com/server/current/manage/manage-security/manage-connections-and-disks.html

  For information on configuring Couchbase to use SSL, see the following
  documentation https://docs.couchbase.com/server/current/manage/manage-security/manage-certificates.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000428-DB-000386"
  tag "gid": "V-58169"
  tag "rid": "SV-72599r1_rule"
  tag "stig_id": "SRG-APP-000428-DB-000386"
  tag "fix_id": "F-63377r1_fix"
  tag "cci": ["CCI-002475"]
  tag "nist": ["SC-28 (1)", "Rev_4"]

  if input('cb_require_encryption_at_rest') == 'true'
    describe "This test requires a Manual Review: Verify encryption tools are installed on the server" do
      skip "This test requires a Manual Review: Verify encryption tools are installed on the server"
    end
  else
    describe "No information is identified as requiring such protection, this is not a finding." do
      subject { input('cb_require_encryption_at_rest') } 
      it { should eq 'false'}
    end
  end
end
