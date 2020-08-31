# encoding: UTF-8
control "V-61407" do
  desc  "rationale", ""
  desc  "check", "
    If Couchbase password authentication is not used, this is not a finding.
    As the Full Admin, review the password policy set using the following
command:
    $ couchbase-cli setting-password-policy -c <host>:<port> -u <Full Admin> -p
<Password> --get
    Review the output. If \"minLength\" is not equal to 15, this is a finding.
If \"enforceDigits\", \"enforceLowercase\", enforceSpecialChars\", and
\"enforceUppercase\" are not set to \"true\", this is a finding.
  "
  desc  "fix", "
    Change password policy settings to be compliant.
    Couchbase Server 6.0.x and earlier -
    As the Full Admin, change the password policy to an approved setting with
the following command:
    $ couchbase-cli setting-password-policy -c <host>:<port> -u <Full Admin> -p
<Password> --set --min-length 15 --uppercase --lowercase --digit --special-char
    Couchbase Server Version 6.5.x and later -
    As the Full Admin, change the password policy to an approved setting with
the following command:
      $ couchbase-cli setting-password-policy -c <host>:<port> -u <Full Admin>
-p <Password> --set --min-length 15 --uppercase 1 --lowercase 1 --digit 1
--special-char 1
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000164-DB-000401"
  tag "gid": "V-61407"
  tag "rid": "SV-75897r3_rule"
  tag "stig_id": "SRG-APP-000164-DB-000401"
  tag "fix_id": "F-67323r7_fix"
  tag "cci": ["CCI-000192"]
  tag "nist": ["IA-5 (1) (a)", "Rev_4"]
end
