# encoding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'nexpose/version'

Gem::Specification.new do |s|
  s.name                  = 'nexpose'
  s.version               = Nexpose::VERSION
  s.homepage              = 'https://github.com/rapid7/nexpose-client'
  s.summary               = 'Ruby API for Rapid7 Nexpose'
  s.description           = 'This gem provides a Ruby API to the Nexpose vulnerability management product by Rapid7.'
  s.license               = 'BSD'
  s.authors               = ['HD Moore', 'Chris Lee', 'Michael Daines', 'Brandon Turner', 'Gavin Schneider', 'Scott Green']
  s.email                 = ['hd_moore@rapid7.com', 'christopher_lee@rapid7.com', 'michael_daines@rapid7.com', 'brandon_turner@rapid7.com', 'gavin_schneider@rapid7.com', 'scott_green@rapid7.com']
  s.files                 = Dir['[A-Z]*'] + Dir['lib/**/*']
  s.require_paths         = ['lib']
  s.extra_rdoc_files      = ['README.markdown']
  s.required_ruby_version = '>= 1.9'
  s.platform              = 'ruby'

  s.add_runtime_dependency('rex', '~> 2.0.5', '>= 2.0.5')

  s.add_development_dependency('bundler', '~> 1.3')
  s.add_development_dependency('codeclimate-test-reporter', '~> 0.4.6')
  s.add_development_dependency('simplecov', '~> 0.9.1')
  s.add_development_dependency('rspec', '~> 3.2')
  s.add_development_dependency('rubocop', '~> 0.29.0')
  s.add_development_dependency('webmock', '~> 1.20.4')
  s.add_development_dependency('vcr', '~> 2.9.3')
end
