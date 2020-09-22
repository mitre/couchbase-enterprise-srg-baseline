# encoding: UTF-8

control "V-58171" do
  title "Couchbase must implement cryptographic mechanisms preventing the
  unauthorized disclosure of organization-defined information at rest on
  organization-defined information system components."
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
  defined the information to prevent the unauthorized disclosure of
  organization-defined information at rest on organization-defined information
  system components.
  
  If the documentation indicates no information requires such protections,
  this is not a finding.
  
  If any of the information defined as requiring protection is not encrypted
  in a manner that provides the required level of protection and is not
  physically secured to the required level, this is a finding.
  
  As the Full Admin, verify that SSL encryption is enabled:
  $ couchbase-cli ssl-manage -c <host>:<port> -u <Full Admin> -p <Password> 
  --client-auth --extended

  Review the output. If \"state\" is not set to \"enabled\" or \"mandatory\", 
  this is a finding.

  If an encryption at rest is required but the encryption tool is not
  installed on the server, this is a finding.
  "
  desc  "fix", "
  Configure Couchbase to provide the required level of cryptographic
  protection for information requiring cryptographic protection against
  disclosure.
  
  Secure the premises, equipment, and media to provide the required level of
  physical protection.
  
  Review  documentation to set up 3rd party encryption tools.
  https://docs.couchbase.com/server/current/manage/manage-security/manage-connections-and-disks.html

  For information on configuring Couchbase to use SSL, see the following
  documentation https://docs.couchbase.com/server/current/manage/manage-security/manage-certificates.html
 "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000429-DB-000387"
  tag "gid": "V-58171"
  tag "rid": "SV-72601r1_rule"
  tag "stig_id": "SRG-APP-000429-DB-000387"
  tag "fix_id": "F-63379r1_fix"
  tag "cci": ["CCI-002476"]
  tag "nist": ["SC-28 (1)", "Rev_4"]
  
  describe "Couchbase should have SSL enabled" do
    subject { json( command: "couchbase-cli ssl-manage -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --client-auth --extended") }
    its('state') { should eq 'enable' }
  end   

  describe "This test requires a Manual Review: Ensure any information defined as requiring protection 
  is encrypted in a manner that provides the required level of protection and is physically secured to
  the required level " do
    skip "This test requires a Manual Review: Ensure any information defined as requiring protection 
    is encrypted in a manner that provides the required level of protection and is physically secured to
    the required level"
  end 
     
  describe "This test requires a Manual Review: Verify if encryption at rest is required 
  that encryption tools are installed on the server" do
    skip "This test requires a Manual Review: Verify if encryption at rest is required 
    that encryption tools are installed on the server"
  end
end
