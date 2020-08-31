# encoding: UTF-8

control "V-58173" do
  title "Couchbase must maintain a separate execution domain for each executing
process."
  desc  "Database management systems can maintain separate execution domains
for each executing process by assigning each process a separate address space.
Each process has a distinct address space so that communication between
processes is controlled through the security functions, and one process cannot
modify the executing code of another process. Maintaining separate execution
domains for executing processes can be achieved, for example, by implementing
separate address spaces."
  desc  "check", "
    If Couchbase is running within a Docker container, this is not a finding.
    Review Couchbase architecture to find out if and how it protects the
private resources of one process (such as working memory, temporary tables,
uncommitted data and, especially, executable code) from unauthorized access or
modification by another user or process.
    If it is not capable of maintaining a separate execution domain for each
executing process, this is a finding.
    If Couchbase is capable of maintaining a separate execution domain for each
executing process, but is configured not to do so, this is a finding.
  "
  desc  "fix", "
    Ensure Couchbase is able to maintain a separate execution domain for each
executing process.
    If this is a configurable feature, configure Couchbase to implement it.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000431-DB-000388"
  tag "gid": "V-58173"
  tag "rid": "SV-72603r1_rule"
  tag "stig_id": "SRG-APP-000431-DB-000388"
  tag "fix_id": "F-63381r1_fix"
  tag "cci": ["CCI-002530"]
  tag "nist": ["SC-39", "Rev_4"]
end
