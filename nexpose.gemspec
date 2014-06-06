# encoding: utf-8

Gem::Specification.new do |s|
  s.name                  = 'nexpose'
  s.version               = '0.7.6'
  s.homepage              = 'https://github.com/rapid7/nexpose-client'
  s.summary               = 'Ruby API for Rapid7 Nexpose'
  s.description           = 'This gem provides a Ruby API to the Nexpose vulnerability management product by Rapid7.'
  s.license               = 'BSD'
  s.authors               = ['HD Moore', 'Chris Lee', 'Michael Daines']
  s.email                 = ['hdm@metasploit.com', 'christopher_lee@rapid7.com', 'michael_daines@rapid7.com']
  s.files                 = Dir['[A-Z]*'] + Dir['lib/**/*']
  s.require_paths         = ['lib']
  s.extra_rdoc_files      = ['README.markdown']
  s.required_ruby_version = '>= 1.9'
  s.platform              = 'ruby'

  s.add_runtime_dependency('librex', '~> 0.0', '>= 0.0.68')
  s.add_runtime_dependency('rex', '~> 1.0', '>= 1.0.2')
end
