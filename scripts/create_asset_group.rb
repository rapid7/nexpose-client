#!/usr/bin/env ruby
require 'nexpose'
require 'optparse'
require 'highline/import'

# Default values
@host = 'localhost'
@port = 3780
@user = 'nxadmin'
@name = @desc = nil

OptionParser.new do |opts|
  opts.banner = "Usage: #{File::basename($0)} [options]"
  opts.separator ''
  opts.separator 'Create an asset group based upon an input file, one IP per line.'
  opts.separator ''
  opts.separator 'By default, it uses the name of the file as the name of the asset group.'
  opts.separator 'As currently written, the script will only asset per IP address.'
  opts.separator 'If multiple sites have the same IP, it is non-deterministic which asset it will choose.'
  opts.separator ''
  opts.separator 'Note that this script will always prompt for a connection password.'
  opts.separator ''
  opts.separator 'Options:'
  opts.on('-n', '--name [NAME]', 'Name to use for new asset group. Must not already exist.') { |name| @name = name }
  opts.on('-d', '--desc [DESCRIPTION]', 'Description to use for new asset group.') { |desc| @desc = desc }
  opts.on('-h', '--host [HOST]', 'IP or hostname of Nexpose console. Default: localhost') { |host| @host = host }
  opts.on('-p', '--port [PORT]', Integer, 'Port of Nexpose console. Default: 3780') { |port| @port = port }
  opts.on('-u', '--user [USER]', 'Username to connect to Nexpose with. Default: nxadmin') { |user| @user = user }
  opts.on('-x', '--debug', 'Report duplicate IP addresses to STDERR.') { |debug| @debug = debug }
  opts.on_tail('--help', 'Print this help message.') { puts opts; exit }
end.parse!

# Any arguments after flags can be grabbed now."
unless ARGV[0]
  $stderr.puts 'Input file is required.'
  exit(1)
end
file = ARGV[0]
@name = File.basename(file, File.extname(file)) unless @name

def get_password(prompt = 'Password: ')
  ask(prompt) { |query| query.echo = false }
end
@password = get_password

# This will fail if the file cannot be read.
ips = File.read(file).split.uniq

nsc = Nexpose::Connection.new(@host, @user, @password, @port)
nsc.login

# Create a map of all assets by IP to make them quicker to find.
all_assets = nsc.assets.reduce({}) do |hash, dev|
  $stderr.puts("Duplicate asset: #{dev.address}") if @debug and hash.member? dev.address 
  hash[dev.address] = dev
  hash
end

# Drop the connection, in case group creation takes too long.
nsc.logout

group = Nexpose::AssetGroup.new(@name, @desc)

ips.each do |ip|
  if all_assets.member? ip
    group.devices << all_assets[ip]
  elsif @debug
    $stderr.puts("No asset with IP #{ip} found.")
  end
end

nsc.login
at_exit { nsc.logout }
group.save(nsc)
puts "Group '#{@name}' saved with #{group.devices.size} assets."
