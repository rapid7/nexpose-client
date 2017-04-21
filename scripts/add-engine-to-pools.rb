#!/usr/bin/env ruby

require 'nexpose'
require 'io/console'
require 'optparse'

include Nexpose

DEFAULT_ENGINE_POOL = "Default Engine Pool"

@port = 3780
@file = nil
@username = nil

@retval = 0

if __FILE__ == $0
  begin
    STDOUT.sync = true
    OptionParser.new do |opt|
      opt.banner = "Usage: #{File::basename($0)} <nexpose_host> <engine> <input_file> [options]"
      opt.on('-p', '--port PORT', 'The Nexpose listening port') { |o| @port = o }
      opt.on('-l', '--login LOGIN_NAME', 'The login name to use') { |o| @username = o }
      opt.on_tail('-h', '--help', 'Print this help message.') { puts opt; exit }
    end.parse!

    hostname = ARGV.shift
    engine_name = ARGV.shift
    filename = ARGV.shift

    port = Integer(@port)
    username = @username


    raise OptionParser::MissingArgument, "You must specify the nexpose host." unless hostname
    raise OptionParser::MissingArgument, "You must specify the engine that will be removed from pools" unless engine_name
    raise OptionParser::MissingArgument, "You must specify the file containing the name of engine pools" unless filename
    raise IOError, "File not found" unless File.file? filename

    puts "Enter your Nexpose credentials."
    print "Username: " unless username
    username = username || gets()
    print "Password: "
    password = STDIN.noecho(&:gets)
    puts ""
    username = username.chomp 
    password = password.chomp
    
    nsc = Connection.new(hostname, username, password, port)
    nsc.login

    engine = nsc.engines.each.find { |e| e.name == engine_name }
    raise 'Engine not found' unless engine 

    pools_to_save = []

    @file = File.open(filename)
    print "Adding engine to pools"
    @file.each_line do |line|
      pool_name = line.chomp
      pool = EnginePool.load(nsc, pool_name)
      pool.engines << engine
      pools_to_save << pool
      print "."
    end
    puts "Done!"
    
    print "Saving pools..."
    pools_to_save.each { |pool| pool.save(nsc); print "." }
    puts "Done!"
  rescue ArgumentError => ex
    puts "Port must be an integer"
    @retval = 1

  rescue SocketError => ex
    puts ex
    @retval = 1

  rescue APIError => ex
    puts ex.reason
    @retval = 1

  rescue IOError, SystemCallError => ex
    puts ex
    @retval = 1

  rescue RuntimeError => ex
    puts ex
    @retval = 1

  rescue Exception => ex
    puts ex
    @retval = 1

  ensure
    nsc.logout if nsc.session_id rescue nil
    @file.close if @file rescue nil
    exit @retval
  end
end
