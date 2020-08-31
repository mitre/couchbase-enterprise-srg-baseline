# encoding: UTF-8

control "V-58097" do
  title "Couchbase must generate audit records when unsuccessful attempts to
access categories of information (e.g., classification levels/security levels)
occur."
  desc  "Changes in categories of information must be tracked. Without an audit
trail, unauthorized access to protected data could go undetected.

    To aid in diagnosis, it is necessary to keep track of failed attempts in
addition to the successful ones.

    For detailed information on categorizing information, refer to FIPS
Publication 199, Standards for Security Categorization of Federal Information
and Information Systems, and FIPS Publication 200, Minimum Security
Requirements for Federal Information and Information Systems.
  "
  desc  "rationale", ""
  desc  "check", "
    Review Couchbase documentation to verify that audit records can be produced
when the system denies or fails to complete attempts to access categories of
information, such access to include reads, creations, modifications and
deletions.
    If Couchbase is not capable of this, this is a finding.
    Review the Couchbase security and audit configurations to verify that audit
records are produced when the system denies attempts to access categories of
information, such access to include reads, creations, modifications and
deletions.
    If they are not produced, this is a finding.
    Review the Couchbase security and audit configurations to verify that audit
records are produced when other errors prevent attempts to access categories of
information, such access to include reads, creations, modifications and
deletions.
    If they are not produced, this is a finding.
  "
  desc  "fix", "
    Deploy Couchbase database capable of producing the required audit records
when it denies or fails to complete access to categories of information.
    Configure Couchbase to produce audit records when it denies access to
categories of information, such access to include reads, creations,
modifications and deletions.
    Configure Couchbase to produce audit records when other errors prevent
access to categories of information, such access to include reads, creations,
modifications and deletions.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000494-DB-000345"
  tag "gid": "V-58097"
  tag "rid": "SV-72527r1_rule"
  tag "stig_id": "SRG-APP-000494-DB-000345"
  tag "fix_id": "F-63305r1_fix"
  tag "cci": ["CCI-000172"]
  tag "nist": ["AU-12 c", "Rev_4"]
end
