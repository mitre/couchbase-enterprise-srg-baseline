# encoding: UTF-8

control "V-32478" do
  title "Couchbase must map the PKI-authenticated identity to an associated
user account."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.
Once a PKI certificate has been validated, it must be mapped to a Couchbase
user account for the authenticated identity to be meaningful to Couchbase and
useful for authorization decisions."
  desc  "rationale", ""
  desc  "check", "
    If Couchbase is not using PKI-based authentication, this check is Not
Applicable (NA).
    The cn (Common Name) attribute of the certificate will be compared to the
requested database user name, and if they match the login will be allowed.
    As the Full Admin, get a list of all RBAC users in the cluster with the
following command:
     $ couchbase-cli user-manage -c <host>:<port> -u <Full Admin> -p <Password>
--list
    To check the cn of the certificate, using openssl, do the following:
    $ openssl x509 -noout -subject -in client_cert
    If the cn does not match the users listed in Couchbase and no user mapping
is used, this is a finding.
    If user accounts are not being mapped to authenticated identities, this is
a finding.
  "
  desc  "fix", "
    Configure the Couchbase to map the authenticated identity directly to the
Couchbase user account.
    For information on configuring Couchbase to use SSL, see the following
documentationhttps://docs.couchbase.com/server/current/manage/manage-security/manage-certificates.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000177-DB-000069"
  tag "gid": "V-32478"
  tag "rid": "SV-42815r3_rule"
  tag "stig_id": "SRG-APP-000177-DB-000069"
  tag "fix_id": "F-36392r2_fix"
  tag "cci": ["CCI-000187"]
  tag "nist": ["IA-5 (2) (c)", "Rev_4"]
end
