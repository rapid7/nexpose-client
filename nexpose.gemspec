# encoding: utf-8
$:.push File.expand_path("../lib", __FILE__)
require 'nexpose/version'

Gem::Specification.new do |s|
	s.name                  = Nexpose::APP_NAME
	s.version               = Nexpose::VERSION
	s.homepage              = "https://github.com/rapid7/nexpose-client"
	s.summary               = "Ruby API for Rapid7 NeXpose"
	s.description           = "This gem provides a Ruby API to the NeXpose vulnerability management product by Rapid7. This version is based on Metasploit SVN revision #{Nexpose::REVISION}"
	s.license               = "BSD"
	s.authors               = ["HD Moore", "Chris Lee"]
	s.email		        	    = ["hdm@metasploit.com", "christopher_lee@rapid7.com"]
	s.files                 = Dir['[A-Z]*'] + Dir['lib/**/*']
	s.require_paths         = ["lib"]
	s.extra_rdoc_files      = ["README.markdown"]
	s.required_ruby_version = ">= 1.8.7"
	s.platform              = "ruby"

	s.add_dependency("librex", ">= 0.0.32")
	s.add_dependency("rex", ">= 1.0.2")
end
