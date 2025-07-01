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
  s.license               = 'BSD-3-Clause'
  s.authors               = ['HD Moore', 'Chris Lee', 'Michael Daines', 'Brandon Turner', 'Gavin Schneider', 'Scott Green']
  s.email                 = ['hd_moore@rapid7.com', 'christopher_lee@rapid7.com', 'michael_daines@rapid7.com', 'brandon_turner@rapid7.com', 'gavin_schneider@rapid7.com', 'scott_green@rapid7.com']
  s.files                 = Dir['[A-Z]*'] + Dir['lib/**/*']
  s.require_paths         = ['lib']
  s.extra_rdoc_files      = ['README.markdown']
  s.required_ruby_version = '>= 2.1'
  s.platform              = 'ruby'

  s.add_development_dependency('bundler')
  s.add_development_dependency('codeclimate-test-reporter', '~> 0.4.6')
  s.add_development_dependency('simplecov', '~> 0.9.1')
  s.add_development_dependency('rake')
  s.add_development_dependency('rspec', '~> 3.2')
  s.add_development_dependency('rubocop')
  s.add_development_dependency('webmock', '~> 1.20.4')
  s.add_development_dependency('vcr', '~> 2.9.3')
  s.add_development_dependency('github_changelog_generator')
  s.add_development_dependency('pry', '0.9.12.6')
end
