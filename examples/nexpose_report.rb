#!/usr/bin/env ruby

require 'rubygems'
require 'nexpose'


host = '127.0.0.1'
port = 3780
user = "user"
pass = "password"

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

#report = Nexpose::ReportConfig.new(@nsc)
#report.set_name("Test" + Time.now.to_i.to_s)
#report.set_template_id("audit-report")
#report.addFilter("SiteFilter", site.to_i)
#report.set_format("csv")

report = Nexpose::ReportAdHoc.new(@nsc, 'audit-report', 'csv')
report.addFilter('site', site.to_i)
p report.generate

#gets
#report.saveReport()

#url = nil
#while not url
#  url = @nsc.report_last(report.config_id)
#  select(nil, nil, nil, 10)
#end

#p url
#gets
#data = @nsc.download(url)

#p data
