#!/usr/bin/env ruby
require 'nexpose'
include Nexpose

nsc = Connection.new('host', 'user', 'password')
nsc.login
at_exit { nsc.logout }

asset_count = {}
engine_load = {}

nsc.sites.each do |site|
  asset_count[site.id] = nsc.site_device_listing(site.id).count
  last_scan = nsc.last_scan(site.id)
  engine_load[last_scan.engine_id] ||= 0
  engine_load[last_scan.engine_id] += asset_count[site.id]
end

total_assets = asset_count.values.reduce(0) { |acc, count| acc += count }

engines = nsc.engines
engine_load.each do |id, count|
  name = engines.find { |eng| eng.id == id }.name
  percent = '%.2f' % (count.to_f / total_assets * 100)
  puts "#{name} : #{count} (#{percent}%)"
end
