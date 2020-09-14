# encoding: UTF-8

control "V-58135" do
  title "Couchbase must prohibit user installation of logic modules (stored
  procedures, functions, triggers, views, etc.) without explicit privileged
  status."
  desc  "Allowing regular users to install software, without explicit
  privileges, creates the risk that untested or potentially malicious software
  will be installed on the system. Explicit privileges (escalated or
  administrative privileges) provide the regular user with explicit capabilities
  and control that exceed the rights of a regular user.

  Couchbase functionality and the nature and requirements of databases will
  vary; so while users are not permitted to install unapproved software, there
  may be instances where the organization allows the user to install approved
  software packages such as from an approved software repository. The
  requirements for production servers will be more restrictive than those used
  for development and research.

  Couchbase must enforce software installation by users based upon what types
  of software installations are permitted (e.g., updates and security patches to
  existing software) and what types of installations are prohibited (e.g.,
  software whose pedigree with regard to being potentially malicious is unknown
  or suspect) by the organization).

  In the case of a database management system, this requirement covers stored
  procedures, functions, triggers, views, etc.
  "
  desc  "check", "
  If Couchbase supports only software development, experimentation and/or
  developer-level testing (that is, excluding production systems, integration
  testing, stress testing, and user acceptance testing), this is not a finding.
  Review Couchbase and database security settings with respect to
  non-administrative users ability to create, alter, or replace logic modules,
  to include but not necessarily only stored procedures, functions, triggers, and
  views.
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
    --list
  If any such permissions exist and are not documented and approved, this is
  a finding.
  "
  desc  "fix", "
  Document and obtain approval for any non-administrative users who require
  the ability to create, alter or replace logic modules.
  Implement the approved permissions. Revoke any unapproved permissions.
  To remove undocumented accounts, execute the following command:
    $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
    <host>:<port> --set --delete --rbac-username <username> --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000378-DB-000365"
  tag "gid": "V-58135"
  tag "rid": "SV-72565r1_rule"
  tag "stig_id": "SRG-APP-000378-DB-000365"
  tag "fix_id": "F-63343r1_fix"
  tag "cci": ["CCI-001812"]
  tag "nist": ["CM-11 (2)", "Rev_4"]

  admin_users = []
  json_output = command("couchbase-cli user-manage -u #{input('cb_full_admin')} -p #{input('cb_full_admin_password')} --cluster #{input('cb_cluster_host')}:#{input('cb_cluster_port')} --list | grep -B7 -A3 '\"role\": \"admin\"' | grep 'id'").stdout.split("\n")
  
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
