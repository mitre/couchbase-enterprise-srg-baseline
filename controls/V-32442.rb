# encoding: UTF-8

control "V-32442" do
  title "Couchbase must uniquely identify and authenticate organizational users
  (or processes acting on behalf of organizational users)."
  desc  "To assure accountability and prevent unauthenticated access,
  organizational users must be identified and authenticated to prevent potential
  misuse and compromise of the system.

  Organizational users include organizational employees or individuals the
  organization deems to have equivalent status of employees (e.g., contractors).
  Organizational users (and any processes acting on behalf of users) must be
  uniquely identified and authenticated for all accesses, except the following:

  (i) Accesses explicitly identified and documented by the organization.
  Organizations document specific user actions that can be performed on the
  information system without identification or authentication; and
  (ii) Accesses that occur through authorized use of group authenticators
  without individual authentication. Organizations may require unique
  identification of individuals using shared accounts, for detailed
  accountability of individual activity.
  "
  desc  "check", "
  Review Couchbase settings to determine whether organizational users are
  uniquely identified and authenticated when logging on/connecting to the system.
    
  As the Full Admin, list current users and roles using the following example
  command:
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
    --list
  If organizational users are not uniquely identified and authenticated, this
  is a finding.
  "
  desc  "fix", "
  Configure Couchbase settings to uniquely identify and authenticate all
  organizational users who log on/connect to the system.
    
  To remove undocumented accounts, execute the following command:
    $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
    <host>:<port> --set --delete --rbac-username <username> --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000148-DB-000103"
  tag "gid": "V-32442"
  tag "rid": "SV-42779r4_rule"
  tag "stig_id": "SRG-APP-000148-DB-000103"
  tag "fix_id": "F-36357r2_fix"
  tag "cci": ["CCI-000764"]
  tag "nist": ["IA-2", "Rev_4"]
  
  rbac_accounts = input('cb_admin_users').clone << input('cb_users')
  user_accounts = []
  json_output = command("couchbase-cli user-manage -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} \
  --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --list | grep 'id'").stdout.split("\n")
  json_output.each do |output|
    user_id = command("echo '#{output}' | awk -F '\"' '{print $4}'").stdout.strip
    user_accounts.push(user_id)
  end
  user_accounts.each do |user|
    describe "Each user in the list should be documented. #{user}" do
      subject { user }
      it { should be_in rbac_accounts.uniq.flatten }
    end
  end 
end
