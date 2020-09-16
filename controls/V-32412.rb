# encoding: UTF-8

control "V-32412" do
  title "Database objects (including but not limited to tables, indexes,
storage, stored procedures, functions, triggers, links to software external to
Couchbase, etc.) must be owned by database/Couchbase principals authorized for
ownership."
  desc  "Within the database, object ownership implies full privileges to the
owned object, including the privilege to assign access to the owned objects to
other subjects. Database functions and procedures can be coded using definer's
rights. This allows anyone who utilizes the object to perform the actions if
they were the owner. If not properly managed, this can lead to privileged
actions being taken by unauthorized individuals.

    Conversely, if critical tables or other objects rely on unauthorized owner
accounts, these objects may be lost when an account is removed.
  "
  desc  "check", "
  Review system documentation to identify accounts authorized to own database
  objects. Review accounts that own objects in the database(s).
  
  As the Full Admin, list current users and roles using the following example
  command:
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
    --list
  
  If any database objects are found to be owned by users not authorized to
  own database objects, this is a finding.
  "
  desc  "fix", "
  To remove undocumented accounts, execute the following command:
    $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
    <host>:<port> --set --delete --rbac-username <username> --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000200"
  tag "gid": "V-32412"
  tag "rid": "SV-42749r3_rule"
  tag "stig_id": "SRG-APP-000133-DB-000200"
  tag "fix_id": "F-36327r3_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]

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
