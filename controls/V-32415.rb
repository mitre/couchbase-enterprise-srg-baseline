# encoding: UTF-8

control "V-32415" do
  title "Couchbase must limit privileges to change software modules, to include
  stored procedures, functions and triggers, and links to software external to
  Couchbase."
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
  Only a user with Full Admin role can change database configuration.
  
  As the Full Admin, get a list of all RBAC users with the following command:
    $ couchbase-cli user-manage -c  <localhost>:<port>  -u <Full Admin> -p
    <Password> --list

  If any users have the \"admin\" role that should not, this is a finding.

  Couchbase configuration files directory -
    $ ls -la /opt/couchbase/etc/couchbase

  If the owner and group are not both \"couchbase\" for the configuration directory 
  and files, this is a finding.
  
  If the directory permissions are more permissive than \"700\", this is a finding.

  If the file permissions are more permissive than \"600\", this is a finding.
  "
  desc  "fix", "
  Remove users who should not have Full Admin role. To manage the roles this
  can be done by running the following command (Note: Do not include the
  \"admin\" role in command):
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
     -p <Password> --set --rbac-username <user> --rbac-password <password> \\
     --rbac-name <name> --roles <roles> \\
     --auth-domain <domain>

  As the root or sudo user, change the permission of the following
  directories:
  Couchbase configuration files directory:
    $ chown -R couchbase:couchbase /opt/couchbase/etc/couchbase
    $ chmod 700 /opt/couchbase/etc/couchbase
    $ chmod 600 /opt/couchbase/etc/couchbase/*
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000179"
  tag "gid": "V-32415"
  tag "rid": "SV-42752r3_rule"
  tag "stig_id": "SRG-APP-000133-DB-000179"
  tag "fix_id": "F-36330r2_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]

  admin_users = []
  json_output = command("#{input('cb_bin_dir')}/couchbase-cli user-manage -u #{input('cb_full_admin')} \
  -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
  --list | grep -B7 -A3 '\"role\": \"admin\"' | grep 'id'").stdout.split("\n")
  
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

  describe file(input('cb_config_dir')) do
    its('owner') { should be_in input('cb_service_user') }
    its('group') { should be_in input('cb_service_group') }
    it { should_not be_more_permissive_than('0700') }
  end

  log_files = command("ls -p #{input('cb_config_dir')} | grep -v '/'").stdout.split("\n")

  log_files.each do |file|
    describe file("#{input('cb_config_dir')}/#{file}") do
      its('owner') { should be_in input('cb_service_user') }
      its('group') { should be_in input('cb_service_group') }
      it { should_not be_more_permissive_than('0600') }
    end
  end 
end
