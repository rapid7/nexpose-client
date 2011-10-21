# encoding: utf-8

APP_NAME = "nexpose"
VERSION = "0.0.4"
REVISION = "12878"

Gem::Specification.new do |s|
	s.name                  = APP_NAME
	s.version               = VERSION
	s.homepage              = "http://www.metasploit.com/"
	s.summary               = "Ruby API for Rapid7 NeXpose"
	s.description           = "This gem provides a Ruby API to the NeXpose vulnerability management product by Rapid7. This version is based on Metasploit SVN revision #{REVISION}"
	s.license               = "BSD"
	s.authors               = ["HD Moore", "Chris Lee"]
	s.email		        = ["hdm@metasploit.com", "chris.lee@rapid7.com"]
	s.files                 = Dir['[A-Z]*'] + Dir['lib/**/*']
	s.require_paths         = ["lib"]
	s.extra_rdoc_files      = ["README.markdown"]
	s.required_ruby_version = ">= 1.8.7"
	s.platform              = "ruby"

	s.add_dependency("librex", ">= 0.0.32")
end
