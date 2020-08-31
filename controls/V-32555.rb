# encoding: UTF-8
control "V-32555" do
  desc  "rationale", ""
  desc  "check", "
    Review Couchbase code (stored procedures, functions, and triggers),
application code, settings, column and field definitions, and constraints to
determine whether the database is protected against invalid input.
    If code exists that allows invalid data to be acted upon or input into the
database, this is a finding.
    If column/field definitions do not exist in the database, this is a finding.
    If columns/fields do not contain constraints and validity checking where
required, this is a finding.
    Where a column/field is noted in the system documentation as necessarily
free-form, even though its name and context suggest that it should be strongly
typed and constrained, the absence of these protections is not a finding.
    Where a column/field is clearly identified by name, caption or context as
Notes, Comments, Description, Text, etc., the absence of these protections is
not a finding.
  "
  desc  "fix", "
    Modify database code to properly validate data before it is put into the
database or acted upon by the database.
    Modify the database to contain column/field definitions for each
column/field in the database.
    Modify the database to contain constraints and validity checking on
database columns and tables that require them for data integrity.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-APP-000251-DB-000160"
  tag "gid": "V-32555"
  tag "rid": "SV-42892r4_rule"
  tag "stig_id": "SRG-APP-000251-DB-000160"
  tag "fix_id": "F-36470r3_fix"
  tag "cci": ["CCI-001310"]
  tag "nist": ["SI-10", "Rev_4"]
end
