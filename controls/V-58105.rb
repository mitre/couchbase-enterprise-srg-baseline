# encoding: UTF-8

control 'V-58105' do
  title "The DBMS must generate audit records when unsuccessful attempts to
delete categories of information (e.g., classification levels/security levels)
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
  desc  'rationale', ''
  desc  'check', "
    Review DBMS documentation to verify that audit records can be produced when
the system denies or fails to complete attempts to delete categories of
information.

    If the DBMS is not capable of this, this is a finding.

    Review the DBMS/database security and audit configurations to verify that
audit records are produced when the system denies attempts to delete categories
of information.

    If they are not produced, this is a finding.

    Review the DBMS/database security and audit configurations to verify that
audit records are produced when other errors prevent attempts to delete
categories of information.

    If they are not produced, this is a finding.
  "
  desc  'fix', "
    Deploy a DBMS capable of producing the required audit records when it
denies or fails to complete deletion of categories of information.

    Configure the DBMS to produce audit records when it denies deletion of
categories of information.

    Configure the DBMS to produce audit records when other errors prevent
deletion of categories of information.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000502-DB-000349'
  tag gid: 'V-58105'
  tag rid: 'SV-72535r1_rule'
  tag stig_id: 'SRG-APP-000502-DB-000349'
  tag fix_id: 'F-63313r1_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end

