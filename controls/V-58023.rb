# encoding: UTF-8

control "V-58023" do
  title "Couchbase must prevent non-privileged users from executing privileged
  functions, to include disabling, circumventing, or altering implemented
  security safeguards/countermeasures."
  desc  "Preventing non-privileged users from executing privileged functions
  mitigates the risk that unauthorized individuals or processes may gain
  unnecessary access to information or privileges.

  System documentation should include a definition of the functionality
  considered privileged.

  Depending on circumstances, privileged functions can include, for example,
  establishing accounts, performing system integrity checks, or administering
  cryptographic key management activities. Non-privileged users are individuals
  that do not possess appropriate authorizations. Circumventing intrusion
  detection and prevention mechanisms or malicious code protection mechanisms are
  examples of privileged functions that require protection from non-privileged
  users.

  A privileged function in Couchbase/database context is any operation that
  modifies the structure of the database, its built-in logic, or its security
  settings. This would include all Data Definition Language (DDL) statements and
  all security-related statements. In an SQL environment, it encompasses, but is
  not necessarily limited to:
      CREATE
      ALTER
      DROP
      GRANT
      REVOKE
      DENY

  There may also be Data Manipulation Language (DML) statements that, subject
  to context, should be regarded as privileged. Possible examples include:

      TRUNCATE TABLE;
      DELETE, or
      DELETE affecting more than n rows, for some n, or
      DELETE without a WHERE clause;

      UPDATE or
      UPDATE affecting more than n rows, for some n, or
      UPDATE without a WHERE clause;

  any SELECT, INSERT, UPDATE, or DELETE to an application-defined security
  table executed by other than a security principal.

  Depending on the capabilities of Couchbase and the design of the database
  and associated applications, the prevention of unauthorized use of privileged
  functions may be achieved by means of Couchbase security features, database
  triggers, other mechanisms, or a combination of these.
  "
  desc  "check", "
  Only a user with Full Admin and Security Admin roles can alter or
  reconfigure the security safeguards.
  As the Full Admin, get a list of all RBAC users with the following command:
  $ couchbase-cli user-manage -c  <localhost>:<port>  -u <Full Admin> -p
  <Password> --list
  If any users have the \"admin\" role or \"security_admin\" role that should
  not, this is a finding.
  "
  desc  "fix", "
  Remove users who should not have Full Admin or Security Admin role. To
  manage the roles this can be done by running the following command (Note: Do
  not include the \"admin\" or the \"security_admin\" role in command):
  $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
  -p <Password> --set --rbac-username <user> --rbac-password <password> \\
  --rbac-name <name> --roles <roles> \\
  --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000340-DB-000304"
  tag "gid": "V-58023"
  tag "rid": "SV-72453r1_rule"
  tag "stig_id": "SRG-APP-000340-DB-000304"
  tag "fix_id": "F-63231r1_fix"
  tag "cci": ["CCI-002235"]
  tag "nist": ["AC-6 (10)", "Rev_4"]

  admin_users = []
  json_output = command("#{input('cb_bin_dir')}/couchbase-cli user-manage -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')}\
  --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} \
  --list | grep -B7 -A3 '\"role\": \"admin\"' | grep 'id'").stdout.split("\n")
  
  if json_output.empty?
    describe 'This test is skipped because there are no users found.' do
      skip 'This test is skipped because there are no users found.'
    end 
  else
    json_output.each do |output|
      user = command("echo '#{output}' | awk -F '\"' '{print $4}'").stdout.strip
      admin_users.push(user)
    end

    admin_users.each do |user|
      describe 'Each admin user in the list' do
        subject { user }
        it { should be_in input('cb_admin_users').uniq.flatten }
      end
    end
  end
end
