# encoding: UTF-8

control "V-32424" do
  title "Unused database components, Couchbase software, and database objects
  must be removed."
  desc  "Information systems are capable of providing a wide variety of
  functions and services. Some of the functions and services, provided by
  default, may not be necessary to support essential organizational operations
  (e.g., key missions, functions).

  It is detrimental for software products to provide, or install by default,
  functionality exceeding requirements or mission objectives.

  Couchbases must adhere to the principles of least functionality by
  providing only essential capabilities.
  "
  desc  "check", "
  Review the list of components and features installed with the Couchbase
  database.

  # RHEL/CENT Systems
  $ yum list installed | grep couchbase
  
  # Debian Systems
  $ dpkg --get-selections | grep couchbase
  
  If unused components are installed and are not documented and authorized,
  this is a finding.
  
  If any packages displayed by this command are not being used, this is a
  finding.
  "
  desc  "fix", "Uninstall unused components or features that are installed and
  can be uninstalled. Remove any database objects and applications that are
  installed to support them.
  
  To remove any unused components, as the system administrator, run the
  following:
    # RHEL/CENT Systems
    $ yum remove <package_name>
    
    # Debian Systems
    $ apt-get remove <package_name>"
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000141-DB-000091"
  tag "gid": "V-32424"
  tag "rid": "SV-42761r3_rule"
  tag "stig_id": "SRG-APP-000141-DB-000091"
  tag "fix_id": "F-36339r2_fix"
  tag "cci": ["CCI-000381"]
  tag "nist": ["CM-7 a", "Rev_4"]

  if os.debian?
    dpkg_packages = command("dpkg --get-selections | grep \"couchbase\"").stdout.split("\n")
    dpkg_packages.each do |package|
      package = command("echo #{package} | sed 's/ install$//'").stdout.split
      describe "Only approved packages should be installed. #{package}" do
        subject { package }
        it { should be_in input('cb_debian_approved_packages') }
      end
    end
  elsif os.redhat?
    yum_packages = command("yum list installed | grep \"couchbase\"").stdout.split("\n")
    yum_packages.each do |package|
      package = command("echo #{package} | sed 's/.x86.*//'").stdout.split
      describe "Only approved packages should be installed. #{package}" do
        subject { package }
        it { should be_in input('cb_redhat_approved_packages') }
      end
    end
  end
end
