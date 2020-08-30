# encoding: UTF-8
control "V-32480" do
  desc  "rationale", ""
  desc  "check", "
    As the system administrator, run the following:
    $ openssl version
    If \"fips\" is not included in the openssl version, this is a finding.
  "
  desc  "fix", "
    Configure OpenSSL to meet FIPS Compliance using the following documentation
in section 9.1:
    http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp1758.pdf
    For information on configuring Couchbase to use SSL, see the following
documentationhttps://docs.couchbase.com/server/current/manage/manage-security/manage-certificates.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000179-DB-000114"
  tag "gid": "V-32480"
  tag "rid": "SV-42817r3_rule"
  tag "stig_id": "SRG-APP-000179-DB-000114"
  tag "fix_id": "F-36395r4_fix"
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]
end
