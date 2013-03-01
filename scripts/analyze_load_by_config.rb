#!/usr/bin/env ruby
require 'nexpose'
include Nexpose

nsc = Connection.new('host', 'user', 'password')
nsc.login
at_exit { nsc.logout }

count_by_config = {}

nsc.sites.each do |site|
  config = Site.load(nsc, site.id)
  next if config.scan_template =~ /discovery/

  count_by_config[config.engine] = 0
  config.assets.each do |asset|
    count = 1
    count += (asset.to.to_i - asset.from.to_i) if defined? asset.from and asset.to
    count_by_config[config.engine] += count
  end
end

total = count_by_config.values.reduce(0) { |acc, count| acc += count }

engines = nsc.engines
count_by_config.each do |id, count|
  name = engines.find { |eng| eng.id == id }.name
  percent = '%.2f' % (count.to_f / total * 100)
  puts "#{name} : #{count} (#{percent}%)"
end
