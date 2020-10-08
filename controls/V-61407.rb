# encoding: UTF-8
control "V-61407" do
  title "If Couchbase authentication, using passwords, is employed, Couchbase
  must enforce the DoD standards for password complexity and lifetime"
  desc  "OS/enterprise authentication and identification must be used
  (SRG-APP-000023-DB-000001).  Native Couchbase authentication may be used only
  when circumstances make it unavoidable; and must be documented and AO-approved.

  The DoD standard for authentication is DoD-approved PKI certificates.
  Authentication based on User ID and Password may be used only when it is not
  possible to employ a PKI certificate, and requires AO approval.

  In such cases, the DoD standards for password complexity and lifetime must
  be implemented.  Couchbase products that can inherit the rules for these from
  the operating system or access control program (e.g., Microsoft Active
  Directory) must be configured to do so.  For other Couchbases, the rules must
  be enforced using available configuration parameters or custom code.
  "
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

  describe "Couchbase password policy settings should be compliant to secure practices." do 
    subject{ json( command: "#{input('cb_bin_dir')}/couchbase-cli setting-password-policy -c #{input('cb_cluster_host')}:#{input('cb_cluster_port')}\
    -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --get")}
    its('minLength') { should cmp '15' }
    its('enforceDigits') { should cmp 'true' }
    its('enforceLowercase') { should cmp 'true' }
    its('enforceSpecialChars') { should cmp 'true' }
    its('enforceUppercase') { should cmp 'true' }
  end
end
