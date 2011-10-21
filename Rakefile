# encoding: utf-8
 
task :build => :update do
	Rake::Task['clean'].execute
	puts "[*] Building nexpose.gemspec"
	system "gem build nexpose.gemspec &> /dev/null"
end
 
task :release => :build do
	puts "[*] Pushing nexpose to rubygems.org"
	system "gem push nexpose-*.gem &> /dev/null"
	Rake::Task['clean'].execute
end

task :clean do
	system "rm *.gem &> /dev/null"
end

task :update do
	system "rm -f lib/nexpose.rb"
	system "svn export https://metasploit.com/svn/framework3/trunk/lib/rapid7/nexpose.rb lib/nexpose.rb"
end
