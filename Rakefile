# encoding: utf-8
 
task :build do
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
