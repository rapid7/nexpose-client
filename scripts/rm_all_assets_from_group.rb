#!/usr/bin/env ruby
require 'optparse'
require 'rubygems'
require 'highline/import'
require 'nexpose'

@host = 'localhost'
@port = 3780
@user = 'nxadmin'

OptionParser.new do |opts|
  opts.banner = "Usage: ruby #{File::basename($0)} [options] <group-id>"
  opts.separator ''
  opts.separator 'Remove all assets from a group.'
  opts.separator ''
  opts.separator %Q{An asset group must already exist for this script to run against. This script\nwill probably be most useful for removing older assets, for example, when used\nagainst a dynamic asset group defined as\n  "last scan date earlier than 90 days ago".}
  opts.separator ''
  opts.separator 'Note that this script will always prompt for a connection password.'
  opts.separator ''
  opts.separator 'Options:'
  opts.on('-h', '--host HOST', 'IP or hostname of Nexpose console. Defaults to localhost if not provided.') { |host| @host = host }
  opts.on('-p', '--port PORT', Integer, 'Port of Nexpose console. Defaults to 3780 if not provided.') { |port| @port = port }
  opts.on('-u', '--user USER', 'Username to connect to Nexpose with. Defaults to nxadmin if not provided.') { |user| @user = user }
  opts.on('-d', '--dry-run', 'Only print out assets to be deleted, but do not actually delete.') { |d| @dry_run = d }
  opts.on_tail('--help', 'Print this help message.') { puts opts; exit }
end.parse!

# Now grab the group ID from the remaining arguments.
unless ARGV[0]
  $stderr.puts 'Asset group ID is required. Use --help for instructions.'
  exit(1)
end
group_id = ARGV[0]

def get_password(prompt = 'Password: ')
  ask(prompt) { |query| query.echo = false }
end
puts 'Upon entering a password, deletion will begin.'
puts 'Use --dry-run to ensure only the desired assets will be deleted.' unless @dry_run
@password = get_password

nsc = Nexpose::Connection.new(@host, @user, @password, @port)
nsc.login

Nexpose::AssetGroup.load(nsc, group_id).devices.each do |device|
  if @dry_run
    puts "#{device.address} [ID: #{device.id}] Site: #{device.site_id}"
  else
    nsc.delete_device(device.id)
  end
end

nsc.logout
