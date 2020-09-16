# encoding: UTF-8

control "V-32427" do
  title "Access to external executables must be disabled or restricted."
  desc  "If the system were to allow any user to make changes to software
  libraries, then those changes might be implemented without undergoing the
  appropriate testing and approvals that are part of a robust change management
  process.
  
  Accordingly, only qualified and authorized individuals shall be allowed to
  obtain access to information system components for purposes of initiating
  changes, including upgrades and modifications.

  Unmanaged changes that occur to the database software libraries or
  configuration can lead to unauthorized or compromised installations.
  "
  desc  "check", "
  As the Full Admin, list current users and roles using the following example command:
  $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password> --list 
  
  If any users have the \"admin\" role that should not, this is a finding.
  "
  desc  "fix", "  
  Remove users who should not have Full Admin role. To manage the roles this
  can be done by running the following command (Note: Do not include the
  \"admin\" role in command):
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
    -p <Password> --set --rbac-username <user> --rbac-password <password> \\
    --rbac-name <name> --roles <roles> \\
    --auth-domain <domain>"
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000093"
  tag "gid": "V-32427"
  tag "rid": "SV-42764r3_rule"
  tag "stig_id": "SRG-APP-000141-DB-000093"
  tag "fix_id": "F-36341r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  admin_users = []
  json_output = command("couchbase-cli user-manage -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
  --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --list | grep -B7 -A3 '\"role\": \"admin\"' | grep 'id'").stdout.split("\n")
  
  json_output.each do |output|
    user = command("echo '#{output}' | awk -F '\"' '{print $4}'").stdout.strip
    admin_users.push(user)
  end

  admin_users.each do |user|
    describe "Each admin user in the list should be documented. #{user}" do
      subject { user }
      it { should be_in input('cb_admin_users').uniq.flatten }
    end
  end
end
