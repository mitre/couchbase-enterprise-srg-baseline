# encoding: UTF-8

control "V-32397" do
  title "Couchbase must protect its audit features from unauthorized access."
  desc  "Protecting audit data also includes identifying and protecting the
tools used to view and manipulate log data.

    Depending upon the log format and application, system and application log
tools may provide the only means to manipulate and manage application and
system log data. It is, therefore, imperative that access to audit tools be
controlled and protected from unauthorized access.

    Applications providing tools to interface with audit data will leverage
user permissions and roles identifying the user accessing the tools and the
corresponding rights the user enjoys in order make access decisions regarding
the access to audit tools.

    Audit tools include, but are not limited to, OS-provided audit tools,
vendor-provided audit tools, and open source audit tools needed to successfully
view and manipulate audit information system activity and records.

    If an attacker were to gain access to audit tools, he could analyze audit
logs for system weaknesses or weaknesses in the auditing itself. An attacker
could also manipulate logs to hide evidence of malicious activity.
  "
  desc  "check", "
    Only a user with Full Admin role can change auditing controls.
    As the Full Admin, get a list of all RBAC users with the following command:
    $ couchbase-cli user-manage -c  <localhost>:<port>  -u <Full Admin> -p
<Password> --list
    If any users have the \"admin\" role that should not, this is a finding.
    Additionally, the permissions of the config file should also be verified.
This can be done by running the following command:
     $ ls -la /opt/couchbase/etc/couchbase/static_config
    Review the ownership and permissions. If anyone other than couchbase is the
owner and group owner, this is a finding. If permissions are not set to 600,
this is a finding.
  "
  desc  "fix", "
    Remove users who should not have Full Admin role. To manage the roles this
can be done by running the following command (Note: Do not include the
\"admin\" role in command):
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> \\
     -p <Password> --set --rbac-username <user> --rbac-password <password> \\
     --rbac-name <name> --roles <roles> \\
     --auth-domain <domain>
    As the root or sudo user, assign the correct permissions to the config file
fun the following commands:
      $ sudo chown -R couchbase:couchbase
/opt/couchbase/etc/couchbase/static_config
      $ sudo chmod 600 /opt/couchbase/etc/couchbase/static_config
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000121-DB-000202"
  tag "gid": "V-32397"
  tag "rid": "SV-42734r3_rule"
  tag "stig_id": "SRG-APP-000121-DB-000202"
  tag "fix_id": "F-36311r2_fix"
  tag "cci": ["CCI-001493"]
  tag "nist": ["AU-9", "Rev_4"]
end
