# encoding: UTF-8

control 'V-58155' do
  title "The DBMS must maintain the confidentiality and integrity of
information during reception."
  desc  "Information can be either unintentionally or maliciously disclosed or
modified during reception, including, for example, during aggregation, at
protocol transformation points, and during packing/unpacking. These
unauthorized disclosures or modifications compromise the confidentiality or
integrity of the information.

    This requirement applies only to those applications that are either
distributed or can allow access to data nonlocally. Use of this requirement
will be limited to situations where the data owner has a strict requirement for
ensuring data integrity and confidentiality is maintained at every step of the
data transfer and handling process.

    When receiving data, the DBMS, associated applications, and infrastructure
must leverage protection mechanisms.
  "
  desc  'rationale', ''
  desc  'check', "
    If the data owner does not have a strict requirement for ensuring data
integrity and confidentiality is maintained at every step of the data transfer
and handling process, this is not a finding.

    If the DBMS, associated applications, and infrastructure do not employ
protective measures against unauthorized disclosure and modification during
reception, this is a finding.
  "
  desc  'fix', "Implement protective measures against unauthorized disclosure
and modification during reception."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag gid: 'V-58155'
  tag rid: 'SV-72585r1_rule'
  tag stig_id: 'SRG-APP-000442-DB-000379'
  tag fix_id: 'F-63363r1_fix'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end

