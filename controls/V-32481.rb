# encoding: UTF-8

control "V-32481" do
  title "Couchbase must uniquely identify and authenticate non-organizational
users (or processes acting on behalf of non-organizational users)."
  desc  "Non-organizational users include all information system users other
than organizational users, which include organizational employees or
individuals the organization deems to have equivalent status of employees
(e.g., contractors, guest researchers, individuals from allied nations).

    Non-organizational users shall be uniquely identified and authenticated for
all accesses other than those accesses explicitly identified and documented by
the organization when related to the use of anonymous access, such as accessing
a web server.

    Accordingly, a risk assessment is used in determining the authentication
needs of the organization.

    Scalability, practicality, and security are simultaneously considered in
balancing the need to ensure ease of use for access to federal information and
information systems with the need to protect and adequately mitigate risk to
organizational operations, organizational assets, individuals, other
organizations, and the Nation.
  "
  desc  "check", "
    Review Couchbase settings to determine whether non-organizational users are
uniquely identified and authenticated when logging onto the system.
    $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
--list
    If non-organizational users are not uniquely identified and authenticated,
this is a finding.
  "
  desc  "fix", "
    Configure Couchbase settings to uniquely identify and authenticate all
non-organizational users who log onto the system.
    As the Full Admin, delete a user with the following command:
      $ couchbase-cli user-manage -u <Full Admin> -p <Password> --cluster
<host>:<port>  --delete --rbac-username <username> --auth-domain <domain>
    As the Full Admin, create a user with the following command:
      $ couchbase-cli user-manage  -u <Full Admin> -p <Password> --cluster
<host>:<port> --set --rbac-username <username> --rbac-password < user password>
--rbac-name <name> --roles <roles>  --auth-domain <domain>
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000180-DB-000115"
  tag "gid": "V-32481"
  tag "rid": "SV-42818r3_rule"
  tag "stig_id": "SRG-APP-000180-DB-000115"
  tag "fix_id": "F-36396r2_fix"
  tag "cci": ["CCI-000804"]
  tag "nist": ["IA-8", "Rev_4"]
end
