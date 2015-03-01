require 'codeclimate-test-reporter'
require 'simplecov'
require 'vcr'

SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter[
  SimpleCov::Formatter::HTMLFormatter,
  CodeClimate::TestReporter::Formatter
]

VCR.configure do |config|
  config.cassette_library_dir = 'spec/fixtures/cassettes'
  config.filter_sensitive_data('<NEXPOSE_CONSOLE_HOSTNAME>') { ENV['NEXPOSE_HOSTNAME'] }
  config.filter_sensitive_data('<NEXPOSE_CONSOLE_USERNAME>') { ENV['NEXPOSE_USERNAME'] }
  config.filter_sensitive_data('<NEXPOSE_CONSOLE_PASSWORD>') { ENV['NEXPOSE_PASSWORD'] }
  config.hook_into :webmock
end

RSpec.configure do |config|
  config.before(:example, :vcr) do
    unless ENV['NEXPOSE_HOSTNAME'] && ENV['NEXPOSE_USERNAME'] && ENV['NEXPOSE_PASSWORD']
      raise ArgumentError, 'You must set the NEXPOSE_HOSTNAME, NEXPOSE_USERNAME, and NEXPOSE_PASSWORD environment variables.'
    end
  end
end

require_relative './matchers'

SimpleCov.start

require 'nexpose'
