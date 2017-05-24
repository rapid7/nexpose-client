require 'codeclimate-test-reporter'
require 'simplecov'
require 'vcr'
require_relative './matchers'
require_relative './helpers'

SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter[
  SimpleCov::Formatter::HTMLFormatter,
  CodeClimate::TestReporter::Formatter
]

environment_variables_defined =
  ENV['NEXPOSE_HOSTNAME'] && ENV['NEXPOSE_USERNAME'] && ENV['NEXPOSE_PASSWORD']
if ENV['CI'] || !environment_variables_defined
  ENV['NEXPOSE_HOSTNAME'] = 'nexpose.local'
  ENV['NEXPOSE_USERNAME'] = 'johndoe'
  ENV['NEXPOSE_PASSWORD'] = 'password123'
end

RSpec.shared_context 'authenticated for API', :with_api_login do
  let(:console_hostname) { ENV['NEXPOSE_HOSTNAME'] }
  let(:username) { ENV['NEXPOSE_USERNAME'] }
  let(:password) { ENV['NEXPOSE_PASSWORD'] }
  let(:connection) do
    Nexpose::Connection.new(console_hostname, username, password).tap(&:login)
  end
end

VCR.configure do |config|
  config.cassette_library_dir = 'spec/fixtures/cassettes'
  config.filter_sensitive_data('nexpose.local') { ENV['NEXPOSE_HOSTNAME'] }
  config.filter_sensitive_data('johndoe') { ENV['NEXPOSE_USERNAME'] }
  config.filter_sensitive_data('password123') { ENV['NEXPOSE_PASSWORD'] }
  config.hook_into :webmock
  config.ignore_hosts 'codeclimate.com'
end

SimpleCov.start

require 'nexpose'

def testCamelCaseComment(from: 'hound')
end
