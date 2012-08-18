#!/usr/bin/env ruby
require 'nexpose'
include Nexpose

nsc = Connection.new('127.0.0.1', 'user', 'pass')
nsc.login

# Get details of last report run.
last = nsc.report_last(15)
puts "Report ID 15 last run on #{last.generated_on} with a status of #{last.status}."

# Get the configuration of an existing template
template = nsc.get_report_template('audit-report')
  # or ...
template = ReportTemplate.get(nsc, 'audit-report')

# Create a new template based upon an existing one.
template.name = "#{template.name} Copy"
template.id = -1
template.built_in = false
template.show_device_names = true
id = template.save(nsc)
puts "New template saved with ID: #{id}"

# Load existing report configuration.
config = nsc.get_report_config(15)
  # or ...
config = ReportConfig.get(nsc, 15)

# Try to generate a new report from the existing configuration.
summary = config.generate(nsc)
  # or ...
summary = nsc.report_generate(15)
unless summary.status == 'Started'
  puts "Report ID 15 finished on #{summary.generated_on} with a status of #{summary.status}."
else
  puts 'Report ID 15 started.'
end

# Generate a new report and wait for it to finish.
summary = config.generate(nsc, true)
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
  report.delete(nsc)
end

# Get a listing of all PCI-related report templates
pci_templates = nsc.report_template_listing.select { |tmp| tmp.name =~ /PCI/ }
pci_templates.each { |tmp| puts tmp.id }

# Get a listing of all reports IDs successfully generated since 13 Aug 2012.
reports = nsc.report_listing.select do |report|
  report.status == 'Generated' && report.generated_on > '20120813T000000000'
end
reports.each { |report| puts report.config_id }

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

# Generate an Adhoc report.
adhoc = AdhocReportConfig.new('audit-report', 'pdf', 31)
data = adhoc.generate(nsc)
File.open('site-31-audit.pdf', 'w') { |file| file.write(data) }

# Logout your Nexpose connection.
nsc.logout
