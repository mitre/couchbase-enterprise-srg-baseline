# encoding: UTF-8

control 'V-58153' do
  title "The DBMS must maintain the confidentiality and integrity of
information during preparation for transmission."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during preparation for transmission, including, for example, during
aggregation, at protocol transformation points, and during packing/unpacking.
These unauthorized disclosures or modifications compromise the confidentiality
or integrity of the information.

    Use of this requirement will be limited to situations where the data owner
has a strict requirement for ensuring data integrity and confidentiality is
maintained at every step of the data transfer and handling process.

    When transmitting data, the DBMS, associated applications, and
infrastructure must leverage transmission protection mechanisms.
  "
  desc  'rationale', ''
  desc  'check', "
    If the data owner does not have a strict requirement for ensuring data
integrity and confidentiality is maintained at every step of the data transfer
and handling process, this is not a finding.

    If the DBMS does not employ protective measures against unauthorized
disclosure and modification during preparation for transmission, this is a
finding.
  "
  desc  'fix', "Implement protective measures against unauthorized disclosure
and modification during preparation for transmission."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag gid: 'V-58153'
  tag rid: 'SV-72583r1_rule'
  tag stig_id: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-63361r1_fix'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end

