# encoding: UTF-8

control "V-32413" do
  title "Database software, including Couchbase  configuration files, must be
  stored in dedicated directories, or DASD pools, separate from the host OS and
  other applications."

  desc  "When dealing with change control issues, it should be noted any
  changes to the hardware, software, and/or firmware components of the
  information system and/or application can potentially have significant effects
  on the overall security of the system.

  Multiple applications can provide a cumulative negative effect. A
  vulnerability and subsequent exploit to one application can lead to an exploit
  of other applications sharing the same security context. For example, an
  exploit to a web server process that leads to unauthorized administrative
  access to host system directories can most likely lead to a compromise of all
  applications hosted by the same system. Database software not installed using
  dedicated directories both threatens and is threatened by other hosted
  applications. Access controls defined for one application may by default
  provide access to the other application's database objects or directories. Any
  method that provides any level of separation of security context assists in the
  protection between applications.
  "
  desc  "check", "
  If Couchbase is running within a Docker container, this is not a finding.
  
  Review the Couchbase software library directory and note other root
  directories located on the same disk directory or any subdirectories.
    
  If any non-Couchbase software directories exist on the disk directory,
  examine or investigate their use. If any of the directories are used by other
  applications, including third-party applications that use Couchbase, this is a
  finding.
  
  Only applications that are required for the functioning and administration,
  not use, of the Couchbase should be located in the same disk directory as the
  Couchbase software libraries.
  
  If other applications are located in the same directory as Couchbase, this
  is a finding.
  "
  desc  "fix", "Install all applications on directories separate from the
  Couchbase software library directory. Relocate any directories or reinstall
  other application software that currently shares the Couchbase software library
  directory."
  
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000133-DB-000199"
  tag "gid": "V-32413"
  tag "rid": "SV-42750r3_rule"
  tag "stig_id": "SRG-APP-000133-DB-000199"
  tag "fix_id": "F-36328r2_fix"
  tag "cci": ["CCI-001499"]
  tag "nist": ["CM-5 (6)", "Rev_4"]
  
  if input('is_docker') == 'true'
    describe "The Couchbase Server is installed within a Docker container so it is 
    separate from the host OS, therefore this is not a finding." do
      subject { virtualization.system }
      it {should cmp 'docker'}
    end
  else
    describe "This test requires a Manual Review: Ensure all database software, 
    including DBMS configuration files, is stored in dedicated directories, or 
    DASD pools, separate from the host OS and other applications." do
      skip "This test requires a Manual Review: Ensure all database software, 
      including DBMS configuration files, is stored in dedicated directories, or 
      DASD pools, separate from the host OS and other applications."
    end
  end  
end
