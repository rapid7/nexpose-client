#!/usr/bin/env ruby

require 'rubygems'
require 'nexpose'


host = '127.0.0.1'
port = 3780
user = "user"
pass = "pass"

@nsc = Nexpose::Connection.new(host, user, pass, port)

@nsc.login

sites = @nsc.site_listing

sites.each do |site|
  p site[:site_id].to_s + ". " + site[:name]
end

site = gets

templates = @nsc.report_template_listing

templates.each do |template|
  p template[:template_id]
end

p "Creating report config"
report = Nexpose::ReportConfig.new(@nsc)
report.set_name("Test" + Time.now.to_i.to_s)
report.set_template_id("audit-report")
report.addFilter("SiteFilter", site.to_i)
report.set_format("raw-xml")

#report = Nexpose::ReportAdHoc.new(@nsc, 'audit-report', 'raw-xml')
#report.addFilter('site', site.to_i)
#p report.generate.to_s

#gets

p "Saving report"
report.saveReport()

url = nil
while not url
  url = @nsc.report_last(report.config_id)
  select(nil, nil, nil, 10)
end

p url
#gets
data = @nsc.download(url)

p data.inspect
