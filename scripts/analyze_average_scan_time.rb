#!/usr/bin/env ruby
require 'nexpose'
include Nexpose

# Note, this doesn't calculate the desired value across paused scans.

nsc = Connection.new('host', 'user', 'password')
nsc.login
at_exit { nsc.logout }

engine_times = {}
engine_assets = {}

nsc.sites.each do |site|
  config = Site.load(nsc, site.id)
  next unless config.scan_template =~ /full-audit/
  # puts "Gathering data for site '#{site.name}'."

  scan_history = nsc.site_scan_history(site.id)

  scan_history.each do |scan|
    next unless scan.end_time # Skip running scans.
    engine = scan.engine_id
    live = scan.nodes.live if scan.nodes
    start_time = scan.start_time
    end_time = scan.end_time

    if live
      engine_times[engine] ||= 0
      engine_times[engine] += (end_time - start_time)
      engine_assets[engine] ||= 0
      engine_assets[engine] += live
    end
  end
end

engines = nsc.engines
engine_times.each do |id, time|
  name = engines.find { |eng| eng.id == id }.name
  avg_time = '%.2f' % (time / engine_assets[id] / 60)
  puts "#{name} : #{avg_time} minutes / asset"
end
