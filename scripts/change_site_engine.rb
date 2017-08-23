# frozen_string_literal: true

# !/usr/bin/env ruby
require 'nexpose'
require 'io/console'
require 'optparse'
require 'csv'

include Nexpose

CSV_HEADER = 'Site ID,Site Name'
@src_engine = nil
@output_file = nil
@input_file = nil
@username = nil
@port = 3780
@retval = 0

def output(msg)
  if @output_file
    @output_file.puts msg
  else
    puts msg
  end
end

if __FILE__ == $PROGRAM_NAME
  # Variable Declaration
  src_id = nil
  dst_id = nil
  sites_to_save = []
  nsc = nil

  begin
    STDOUT.sync = true
    OptionParser.new do |opt|
      opt.banner = "Usage: #{$PROGRAM_NAME} <nexpose_host> <dst_engine> <-s src_engine | -i input_file> [options]"
      opt.on('-p',
             '--port PORT',
             'The Nexpose listening port') { |o| @port = o }
      opt.on('-s',
             '--source-engine SRC_ENGINE',
             'The engine from which the sites will be moved') { |o| @src_engine = o }
      opt.on('-o',
             '--output FILE',
             'The output FILE where the touched sites will be written') { |o| @output_file = File.open(o, 'w') }
      opt.on('-i',
             '--input FILENAME',
             'The file containing the list of sites to which change the engine') { |o| @input_file = CSV.open(o, 'r') }
      opt.on('-l',
             '--login LOGIN_NAME',
             'The login name to use') { |o| @username = o }
      opt.on_tail('-h', '--help', 'Print this help message.') do
        puts opt
        exit 0
      end
    end.parse!

    hostname = ARGV.shift
    dst_engine = ARGV.shift
    port = Integer(@port)
    username = @username
    src_engine = @src_engine

    valid_argument = !src_engine.nil? ^ !@input_file.nil? # XOR

    raise OptionParser::MissingArgument, 'Specify the nexpose host.' unless hostname
    raise OptionParser::MissingArgument, 'Specify the engine in which the sites will be moved' unless dst_engine
    raise OptionParser::InvalidArgument, 'Specify either the source engine or the filename' unless valid_argument

    puts 'Enter your Nexpose credentials.'
    print 'Username: ' unless username
    username ||= gets
    print 'Password: '
    password = STDIN.noecho(&:gets)
    puts ''
    username = username.chomp
    password = password.chomp

    nsc = Connection.new(hostname, username, password, port)
    nsc.login

    nsc.engines.each do |engine|
      if engine.name == src_engine
        src_id = engine.id
      elsif engine.name == dst_engine
        dst_id = engine.id
      end
    end

    raise 'Source engine not found' if src_engine && !src_id
    raise 'Destination engine not found' unless dst_id

    print 'Loading sites'
    sites = []
    if src_id
      nsc.sites.each do |s|
        site = Site.load(nsc, s.id)
        if site.engine_id == src_id
          sites.push site
          print '.'
        end
      end
    else
      @input_file.shift # Skip header row
      @input_file.each do |line|
        site_id, site_name = line
        site = Site.load(nsc, site_id)
        raise 'ERROR: Data inconsistency!' if site.name != site_name
        sites.push site
        print '.'
      end
    end
    puts 'Done!'

    print 'Changing engine on sites'
    sites.each do |site|
      site.engine_id = dst_id
      sites_to_save.push site
      print '.'
    end
    puts 'Done!'

    print 'Saving sites'
    output CSV_HEADER
    sites_to_save.each do |site|
      output "#{site.id},#{site.name}"
      site.save(nsc)
      print '.'
    end
    puts 'Done!'
  rescue ArgumentError
    puts 'Port must be an integer'
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
  rescue StandardError => ex
    puts ex, ex.class
    @retval = 1
  ensure
    nsc&.logout if nsc&.session_id
    @output_file&.close
    @input_file&.close
    exit @retval
  end
end
