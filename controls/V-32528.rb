# encoding: UTF-8
control "V-32528" do
  desc  "rationale", ""
  desc  "check", "
    Couchbase is capable of replicating data across different clusters, by
means of the Database Change Protocol (DCP).
    As the Full Admin, execute the following command to list the current XDCR
replication:
      $ couchbase-cli xdcr-replicate -c <host>:<port> -u <Full Admin> -p
<Password> --list
    If the list is empty, XDCR replication is not being utilized by the
cluster, therefore this is a finding.
  "
  desc  "fix", "
    As the Full Admin, setup XDCR for Couchbase with the following command:
     $ couchbase-cli xdcr-setup -c <host>:<port>-u <Full Admin> -p <Password>
--create \\
    --xdcr-cluster-name <remote-cluster>--xdcr-hostname <host>:<port>
--xdcr-username \\
    <Full Admin> --xdcr-password <Password>
      $ couchbase-cli xdcr-replicate -c <host>:<port>-u <Full Admin> \\
       -p <Password> --create --xdcr-cluster-name <remote-cluster>
--xdcr-from-bucket    <bucket> --xdcr-to-bucket <remote-bucket>
--xdcr-replication-mode xmem
    Review XDCR setup documentation for Couchbase:
https://docs.couchbase.com/server/current/cli/cbcli/couchbase-cli-xdcr-setup.html
https://docs.couchbase.com/server/current/cli/cbcli/couchbase-cli-xdcr-replicate.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000225-DB-000153"
  tag "gid": "V-32528"
  tag "rid": "SV-42865r3_rule"
  tag "stig_id": "SRG-APP-000225-DB-000153"
  tag "fix_id": "F-36443r2_fix"
  tag "cci": ["CCI-001190"]
  tag "nist": ["SC-24", "Rev_4"]
end
