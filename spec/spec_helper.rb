require 'codeclimate-test-reporter'
require 'simplecov'
require 'vcr'
require_relative './matchers'

SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter[
  SimpleCov::Formatter::HTMLFormatter,
  CodeClimate::TestReporter::Formatter
]

if ENV['CI']
  ENV['NEXPOSE_HOSTNAME'] = 'nexpose.local'
  ENV['NEXPOSE_USERNAME'] = 'johndoe'
  ENV['NEXPOSE_PASSWORD'] = 'password123'
end

VCR.configure do |config|
  config.cassette_library_dir = 'spec/fixtures/cassettes'
  config.filter_sensitive_data('nexpose.local') { ENV['NEXPOSE_HOSTNAME'] }
  config.filter_sensitive_data('johndoe') { ENV['NEXPOSE_USERNAME'] }
  config.filter_sensitive_data('password123') { ENV['NEXPOSE_PASSWORD'] }
  config.hook_into :webmock
end

SimpleCov.start

require 'nexpose'
