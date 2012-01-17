module Nexpose
	module NexposeAPI
		include XMLUtils

		def scan_stop(param)
			r = execute(make_xml('ScanStopRequest', {'scan-id' => param}))
			r.success
		end

		def scan_status(param)
			r = execute(make_xml('ScanStatusRequest', {'scan-id' => param}))
			r.success ? r.attributes['status'] : nil
		end

		def scan_activity
			r = execute(make_xml('ScanActivityRequest', {}))
			if (r.success)
				res = []
				r.res.elements.each("//ScanSummary") do |scan|
					res << {
						:scan_id => scan.attributes['scan-id'].to_i,
						:site_id => scan.attributes['site-id'].to_i,
						:engine_id => scan.attributes['engine-id'].to_i,
						:status => scan.attributes['status'].to_s,
						:start_time => Date.parse(scan.attributes['startTime'].to_s).to_time
					}
				end
				res
			else
				false
			end
		end

		def scan_statistics(param)
			r = execute(make_xml('ScanStatisticsRequest', {'scan-id' => param}))
			if (r.success)
				res = {}
				r.res.elements.each("//ScanSummary/nodes") do |node|
					res[:nodes] = {}
					node.attributes.keys.each do |k|
						res[:nodes][k] = node.attributes[k].to_i
					end
				end
				r.res.elements.each("//ScanSummary/tasks") do |task|
					res[:task] = {}
					task.attributes.keys.each do |k|
						res[:task][k] = task.attributes[k].to_i
					end
				end
				r.res.elements.each("//ScanSummary/vulnerabilities") do |vuln|
					res[:vulns] ||= {}
					k = vuln.attributes['status'] + (vuln.attributes['severity'] ? ("-" + vuln.attributes['severity']) : '')
					res[:vulns][k] = vuln.attributes['count'].to_i
				end
				r.res.elements.each("//ScanSummary") do |summ|
					res[:summary] = {}
					summ.attributes.keys.each do |k|
						res[:summary][k] = summ.attributes[k]
						if (res[:summary][k] =~ /^\d+$/)
							res[:summary][k] = res[:summary][k].to_i
						end
					end
				end
				r.res.elements.each("//ScanSummary/message") do |message|
					res[:message] = message.text
				end
				res
			else
				false
			end
		end
	end

	# === Description
	# Object that represents a summary of a scan.
	#
	class ScanSummary
		# The Scan ID of the Scan
		attr_reader :scan_id
		# The Engine ID used to perform the scan
		attr_reader :engine_id
		# TODO: add description
		attr_reader :name
		# The scan start time
		attr_reader :startTime
		# The scan finish time
		attr_reader :endTime
		# The scan status (running|finished|stopped|error| dispatched|paused|aborted|uknown)
		attr_reader :status
		# The number of pending tasks
		attr_reader :tasks_pending
		# The number of active tasks
		attr_reader :tasks_active
		# The number of completed tasks
		attr_reader :tasks_completed
		# The number of "live" nodes
		attr_reader :nodes_live
		# The number of "dead" nodes
		attr_reader :nodes_dead
		# The number of filtered nodes
		attr_reader :nodes_filtered
		# The number of unresolved nodes
		attr_reader :nodes_unresolved
		# The number of "other" nodes
		attr_reader :nodes_other
		# Confirmed vulnerabilities found (indexed by severity)
		# Associative array, indexed by severity
		attr_reader :vuln_exploit
		# Unconfirmed vulnerabilities found (indexed by severity)
		# Associative array, indexed by severity
		attr_reader :vuln_version
		# Not vulnerable checks run (confirmed)
		attr_reader :not_vuln_exploit
		# Not vulnerable checks run (unconfirmed)
		attr_reader :not_vuln_version
		# Vulnerability check errors
		attr_reader :vuln_error
		# Vulnerability checks disabled
		attr_reader :vuln_disabled
		# Vulnerability checks other
		attr_reader :vuln_other

		# Constructor
		# ScanSummary(can_id, $engine_id, $name, tartTime, $endTime, tatus)
		def initialize(scan_id, engine_id, name, startTime, endTime, status)

			@scan_id = scan_id
			@engine_id = engine_id
			@name = name
			@startTime = startTime
			@endTime = endTime
			@status = status

		end

	end

	# TODO
	# === Description
	# Object that represents the overview statistics for a particular scan.
	#
	# === Examples
	#
	#   # Create a new Nexpose Connection on the default port and Login
	#   nsc = Connection.new("10.1.40.10","nxadmin","password")
	#   nsc.login()
	#
	#   # Get a Site (Site ID = 12) from the NSC
	#   site = new Site(nsc,12)
	#
	#   # Start a Scan of this site and pause for 1 minute
	#   scan1 = site.scanSite()
	#   sleep(60)
	#
	#   # Get the Scan Statistics for this scan
	#   scanStatistics = new ScanStatistics(nsc,scan1["scan_id"])
	#
	#   # Print out number of confirmed vulnerabilities with a 10 severity
	#   puts scanStatistics.scansummary.vuln_exploit[10]
	#
	#   # Print out the number of pending tasks left in the scan
	#   puts scanStatistics.scan_summary.tasks_pending
	#
	class ScanStatistics
		# true if an error condition exists; false otherwise
		attr_reader :error
		# Error message string
		attr_reader :error_msg
		# The last XML request sent by this object
		attr_reader :request_xml
		# The last XML response received by this object
		attr_reader :reseponse_xml
		# The Scan ID
		attr_reader :scan_id
		# The ScanSummary of the scan
		attr_reader :scan_summary
		# The NSC Connection associated with this object
		attr_reader :connection

		# Vulnerability checks other
		attr_reader :vuln_other

		def initialize(connection, scan_id)
			@error = false
			@connection = connection
			@scan_id = scan_id
		end
	end

	# TODO add engineID
	# === Description
	# Object that represents the scanning configuration for a Site.
	#
	class ScanConfig
		# A unique ID for this scan configuration
		attr_reader :configID
		# The name of the scan template
		attr_reader :name
		# The ID of the scan template used full-audit, exhaustive-audit, web-audit, dos-audit, internet-audit, network-audit
		attr_reader :templateID
		# The configuration version (default is 2)
		attr_reader :configVersion
		# Array of (Schedule)*
		attr_reader :schedules
		# Array of (ScanTrigger)*
		attr_reader :scanTriggers

		def initialize(configID, name, templateID, configVersion = 2)

			@configID = configID
			@name = name
			@templateID = templateID
			@configVersion = configVersion
			@schedules = Array.new()
			@scanTriggers = Array.new()

		end

		# Adds a new Schedule for this ScanConfig
		def addSchedule(schedule)
			@schedules.push(schedule)
		end

		# Adds a new ScanTrigger to the scanTriggers array
		def addScanTrigger(scanTrigger)
			@scanTriggers.push(scanTrigger)
		end

		def _set_configID(configID)
			@configID = configID
		end

		def _set_name(name)
			@name = name
		end

	end

	# TODO: review
	# <scanFilter scanStop='0' scanFailed='0' scanStart='1'/>
	# === Description
	#
	class ScanFilter

		attr_reader :scanStop
		attr_reader :scanFailed
		attr_reader :scanStart

		def initialize(scanstop, scanFailed, scanStart)

			@scanStop = scanStop
			@scanFailed = scanFailed
			@scanStart = scanStart

		end

	end


	# === Description
	# Object that holds an event that triggers the start of a scan.
	#
	class ScanTrigger
		# Type of Trigger (AutoUpdate)
		attr_reader :type
		# Enable or disable this scan trigger
		attr_reader :enabled
		# Sets the trigger to start an incremental scan or a full scan
		attr_reader :incremental

		def initialize(type, incremental, enabled = 1)

			@type = type
			@incremental = incremental
			@enabled = enabled

		end
	end

end