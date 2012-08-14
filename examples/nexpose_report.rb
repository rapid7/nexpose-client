#!/usr/bin/env ruby
require 'nexpose'
include Nexpose

host = '127.0.0.1'
user = 'user'
pass = 'pass'

nsc = Nexpose::Connection.new(host, user, pass)
nsc.login

# Get details of last report run.
last = nsc.report_last(15)
puts "Report ID 15 last run on #{last.generated_on} with a status of #{last.status}."

# Load existing report configuration.
config = nsc.get_report_config(15)
  # or ...
config = ReportConfig.get(nsc, 15)

# Try to generate a new report from the existing configuration.
summary = config.generate(nsc)
  # or ...
summary = nsc.report_generate(15)
puts "Report ID 15 finished on #{summary.generated_on} with a status of #{summary.status}."

# Copy that configuration for a new report.
config.id = -1
config.name = "#{config.name} Copy"

# Save but do not generate a new report.
id = config.save(nsc, false)
puts "Saved report with report ID #{id}."

# Delete failed reports from the report history.
bad_reports = nsc.report_history(15).select do |summary|
  summary.status == 'Failed'
  || summary.status == 'Aborted'
  || summary.status == 'Unknown'
end
bad_reports.each do |report|
  nsc.report_delete(report.id)
end

# Get a listing of all PCI-related report templates
puts nsc.report_template_listing.select { |report| report[:name] =~ /PCI/ }

# Get a listing of all reports successfully generated since 13 Aug 2012.
puts nsc.report_listing.select do |report|
  report[:status] == 'Generated'
  && report[:generated_on] > '20120813T000000000'
end

# Create a new report from scratch and download
report = ReportConfig.new(-1, 'CSV Export', 'basic-vulnerability-check-results', 'csv', 2, 'America/Los_Angeles')
report.filters << Filter.new('site', 31)
id = report.save(nsc, true)
puts "Report saved with ID #{id}"
until nsc.report_last(id)
  puts 'waiting . . .'
end

last = nsc.report_last(id)
data = nsc.download(last.report_uri)
puts data.inspect

nsc.logout
