# encoding: UTF-8

control "V-32480" do
  title "Couchbase must use NIST FIPS 140-2 validated cryptographic modules for
cryptographic operations."
  desc  "Use of weak or not validated cryptographic algorithms undermines the
purposes of utilizing encryption and digital signatures to protect data.  Weak
algorithms can be easily broken and not validated cryptographic modules may not
implement algorithms correctly. Unapproved cryptographic modules or algorithms
should not be relied on for authentication, confidentiality or integrity. Weak
cryptography could allow an attacker to gain access to and modify data stored
in the database as well as the administration settings of Couchbase.

    Applications, including Couchbases, utilizing cryptography are required to
use approved NIST FIPS 140-2 validated cryptographic modules that meet the
requirements of applicable federal laws, Executive Orders, directives,
policies, regulations, standards, and guidance.

    The security functions validated as part of FIPS 140-2 for cryptographic
modules are described in FIPS 140-2 Annex A.

    NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based
encryption modules.
  "
  desc  "check", "
    As the system administrator, run the following:
    $ openssl version
    If \"fips\" is not included in the openssl version, this is a finding.
  "
  desc  "fix", "
    Configure OpenSSL to meet FIPS Compliance using the following documentation
in section 9.1:
    http://csrc.nist.gov/groups/STM/cmvp/documents/140-1/140sp/140sp1758.pdf
    For information on configuring Couchbase to use SSL, see the following
documentationhttps://docs.couchbase.com/server/current/manage/manage-security/manage-certificates.html
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000179-DB-000114"
  tag "gid": "V-32480"
  tag "rid": "SV-42817r3_rule"
  tag "stig_id": "SRG-APP-000179-DB-000114"
  tag "fix_id": "F-36395r4_fix"
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]
end
