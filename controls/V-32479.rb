# encoding: UTF-8

control 'V-32479' do
  title "The DBMS must obscure feedback of authentication information during
the authentication process to protect the information from possible
exploitation/use by unauthorized individuals."
  desc  "The DoD standard for authentication is DoD-approved PKI certificates.

    Normally, with PKI authentication, the interaction with the user for
authentication will be handled by a software component separate from the DBMS,
such as ActivIdentity ActivClient. However, in cases where the DBMS controls
the interaction, this requirement applies.

    To prevent the compromise of authentication information such as passwords
and PINs during the authentication process, the feedback from the system must
not provide any information that would allow an unauthorized user to compromise
the authentication mechanism.

    Obfuscation of user-provided authentication secrets when typed into the
system is a method used in addressing this risk.

    Displaying asterisks when a user types in a password or a smart card PIN is
an example of obscuring feedback of authentication secrets.

    This calls for review of applications, which will require collaboration
with the application developers. It is recognized that in many cases, the
database administrator (DBA) is organizationally separate from the application
developers, and may have limited, if any, access to source code. Nevertheless,
protections of this type are so important to the secure operation of databases
that they must not be ignored. At a minimum, the DBA must attempt to obtain
assurances from the development organization that this issue has been
addressed, and must document what has been discovered.
  "
  desc  'rationale', ''
  desc  'check', "
    If all interaction with the user for purposes of authentication is handled
by a software component separate from the DBMS, this is not a finding.

    If any application, tool or feature associated with the DBMS/database
displays any authentication secrets (to include PINs and passwords) during - or
after - the authentication process, this is a finding.
  "
  desc  'fix', "Modify and configure each non-compliant application, tool, or
feature associated with the DBMS/database so that it does not display
authentication secrets."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000178-DB-000083'
  tag gid: 'V-32479'
  tag rid: 'SV-42816r4_rule'
  tag stig_id: 'SRG-APP-000178-DB-000083'
  tag fix_id: 'F-36393r3_fix'
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end

