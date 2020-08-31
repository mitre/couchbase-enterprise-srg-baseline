# encoding: UTF-8
control "V-32476" do
  desc  "rationale", ""
  desc  "check", "
    If Couchbase is not using PKI-based authentication, this check is Not
Applicable (NA).
    Verify ownership, group ownership, and permissions on the file given for
the private key (default "ca.key").
    Run following command and review its output:
    ls -al <Private Key File Path>/ca.key
    Example Output:
    -rw------- 1 couchbase couchbase 566 Apr 26 20:20  <Private Key File
Path>/ca.key
    If the user owner and group owner are not both \"couchbase\", this is a
finding.
    If the file is more permissive than \"600\", this is a finding.
    Verify ownership, group ownership, and permissions on the file given for CA
file (default "ca.pem").
    Run following command and review its output:
    ls -al <CA File Path>/ca.pem
    Example Output:
    -rw------- 1 couchbase couchbase 566 Apr 26 20:20  <CA File Path>/ca.pem
    If the user owner and group owner are not both \"couchbase\", this is a
finding.
    If the file is more permissive than \"600\", this is a finding.
  "
  desc  "fix", "
    Store all Couchbase PKI private keys in a FIPS 140-2 validated
cryptographic module.
    Ensure access to Couchbase PKI private keys is restricted to only
authenticated and authorized users.
    As the root or sudo user, execute the following commands to set the
ownership and permissions of the private key and certificate files:
    $ chown couchbase:couchbase <Private Key File Path>/ca.key
    $ chmod 600 /etc/ssl/mongodb.pem
    $ chown couchbase:couchbase <Private Key File Path>/ca.pem
    $ chmod 600  <Private Key File Path>/ca.pem
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000176-DB-000068"
  tag "gid": "V-32476"
  tag "rid": "SV-42813r3_rule"
  tag "stig_id": "SRG-APP-000176-DB-000068"
  tag "fix_id": "F-36391r3_fix"
  tag "cci": ["CCI-000186"]
  tag "nist": ["IA-5 (2) (b)", "Rev_4"]
end
