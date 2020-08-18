# encoding: UTF-8

control 'V-32428' do
  title "The DBMS must be configured to prohibit or restrict the use of
organization-defined functions, ports, protocols, and/or services, as defined
in the PPSM CAL and vulnerability assessments."
  desc  "In order to prevent unauthorized connection of devices, unauthorized
transfer of information, or unauthorized tunneling (i.e., embedding of data
types within data types), organizations must disable or restrict unused or
unnecessary physical and logical ports/protocols/services on information
systems.

    Applications are capable of providing a wide variety of functions and
services. Some of the functions and services provided by default may not be
necessary to support essential organizational operations. Additionally, it is
sometimes convenient to provide multiple services from a single component
(e.g., email and web services); however, doing so increases risk over limiting
the services provided by any one component.

    To support the requirements and principles of least functionality, the
application must support the organizational requirements providing only
essential capabilities and limiting the use of ports, protocols, and/or
services to only those required, authorized, and approved to conduct official
business or to address authorized quality of life issues.

    Database Management Systems using ports, protocols, and services deemed
unsafe are open to attack through those ports, protocols, and services. This
can allow unauthorized access to the database and through the database to other
components of the information system.
  "
  desc  'rationale', ''
  desc  'check', "Review the DBMS settings and local documentation for
functions, ports, protocols, and services that are not approved. If any are
found, this is a finding."
  desc  'fix', "Disable functions, ports, protocols, and services that are not
approved."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000142-DB-000094'
  tag gid: 'V-32428'
  tag rid: 'SV-42765r3_rule'
  tag stig_id: 'SRG-APP-000142-DB-000094'
  tag fix_id: 'F-36342r2_fix'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end

