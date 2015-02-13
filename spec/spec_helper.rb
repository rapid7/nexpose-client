require 'codeclimate-test-reporter'
require 'simplecov'
require_relative './helpers'

SimpleCov.formatter = SimpleCov::Formatter::MultiFormatter[
  SimpleCov::Formatter::HTMLFormatter,
  CodeClimate::TestReporter::Formatter
]
SimpleCov.start

require 'nexpose'
