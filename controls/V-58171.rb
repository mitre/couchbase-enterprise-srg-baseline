# encoding: UTF-8
control "V-58171" do
  desc  "rationale", ""
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
end
