# encoding: utf-8

Gem::Specification.new do |s|
  s.name                  = 'nexpose'
  s.version               = '0.8.5'
  s.homepage              = 'https://github.com/rapid7/nexpose-client'
  s.summary               = 'Ruby API for Rapid7 Nexpose'
  s.description           = 'This gem provides a Ruby API to the Nexpose vulnerability management product by Rapid7.'
  s.license               = 'BSD'
  s.authors               = ['HD Moore', 'Chris Lee', 'Michael Daines', 'Brandon Turner']
  s.email                 = ['hd_moore@rapid7.com', 'christopher_lee@rapid7.com', 'michael_daines@rapid7.com', 'brandon_turner@rapid7.com' ]
  s.files                 = Dir['[A-Z]*'] + Dir['lib/**/*']
  s.require_paths         = ['lib']
  s.extra_rdoc_files      = ['README.markdown']
  s.required_ruby_version = '>= 1.9'
  s.platform              = 'ruby'

  s.add_runtime_dependency('rex', '~> 2.0.3', '>= 2.0.3')
  s.add_runtime_dependency('nokogiri', '~> 1.6', '>= 1.6.2')
end
