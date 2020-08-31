# encoding: UTF-8
control "V-58159" do
  desc  "rationale", ""
  desc  "check", "
    As the system administrator, run the following:
    $ openssl version
    If \"fips\" is not included in the openssl version, this is a finding.
    Run the following command to check if the OS has FIPS enabled:
    $ cat /proc/sys/crypto/fips_enabled
    If fips_enabled is not 1, this is a finding.
  "
  desc  "fix", "
    Configure OpenSSL to meet FIPS Compliance.
    To configure OpenSSL to be FIPS 140-2 compliant, see the official RHEL
Documentation:
https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-Federal_Standards_And_Regulations-Federal_Information_Processing_Standard.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000514-DB-000381"
  tag "gid": "V-58159"
  tag "rid": "SV-72589r1_rule"
  tag "stig_id": "SRG-APP-000514-DB-000381"
  tag "fix_id": "F-63367r2_fix"
  tag "cci": ["CCI-002450"]
  tag "nist": ["SC-13", "Rev_4"]
end
