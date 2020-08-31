# encoding: UTF-8
control "V-58169" do
  desc  "rationale", ""
  desc  "check", "
    Review the system documentation to determine whether the organization has
defined the information at rest that is to be protected from modification,
which must include, at a minimum, PII and classified information.
    If no information is identified as requiring such protection, this is not a
finding.
    If any of the information defined as requiring cryptographic protection
from modification is not encrypted in a manner that provides the required level
of protection, this is a finding.
    If an encryption at rest is required but the encryption tool is not
installed on the server, this is a finding.

  "
  desc  "fix", "
    Configure Couchbase settings to enable protections against
man-in-the-middle attacks that guess at session identifier values.
    Review  documentation to set up 3rd party encryption tools.
https://docs.couchbase.com/server/current/manage/manage-security/manage-connections-and-disks.html
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
end
