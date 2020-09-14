# encoding: UTF-8

control "V-58175" do
  title "When updates are applied to Couchbase, any software components that
  have been replaced or made unnecessary must be removed."
  desc  "Previous versions of Couchbase components that are not removed from
  the information system after updates have been installed may be exploited by
  adversaries.

  Some Couchbases' installation tools may remove older versions of software
  automatically from the information system. In other cases, manual review and
  removal will be required. In planning installations and upgrades, organizations
  must include steps (automated, manual, or both) to identify and remove the
  outdated modules.

  A transition period may be necessary when both the old and the new software
  are required. This should be taken into account in the planning.
  "
  desc  "check", "
  Review the list of components and features installed with the Couchbase.
  If unused components are installed and are not documented and authorized,
  this is a finding.
  List the currently installed Couchbase packages:
    $ yum list installed | grep couchbase
  If any packages displayed by this command are not being used, this is a
  finding.
  If software components that have been replaced or made unnecessary are not
  removed, this is a finding.
  "
  desc  "fix", "
  To remove unnecessary software use the following command:
    $ yum remove <package-name>
  "
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000454-DB-000389"
  tag "gid": "V-58175"
  tag "rid": "SV-72605r1_rule"
  tag "stig_id": "SRG-APP-000454-DB-000389"
  tag "fix_id": "F-63383r1_fix"
  tag "cci": ["CCI-002617"]
  tag "nist": ["SI-2 (6)", "Rev_4"]

  if os.debian?
    dpkg_packages = command("apt list --installed | grep \"couchbase\"").stdout.strip.tr(' ','').split("\n")
    dpkg_packages.each do |packages|
      describe(packages) do
        it { should match input('cb_version') }
      end
  end

  elsif os.linux? || os.redhat?
    yum_packages = command("yum -list installed | grep \"couchbase\"").stdout.strip.tr(' ','').split("\n")

    yum_packages.each do |packages|
      describe(packages) do
        it { should match input('cb_version') }
      end
    end
  end
end
