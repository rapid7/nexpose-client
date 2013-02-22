module Nexpose
  module NexposeAPI
    include XMLUtils

    # Stop a running or paused scan.
    #
    # @param [Fixnum] scan_id ID of the scan to stop.
    # @param [Fixnum] wait_sec Number of seconds to wait for status to be updated. Default: 0
    def scan_stop(scan_id, wait_sec = 0)
      r = execute(make_xml('ScanStopRequest', {'scan-id' => scan_id}))
      if r.success
        so_far = 0
        while so_far < wait_sec
          status = scan_status(scan_id)
          return status if status == 'stopped'
          sleep 5
          so_far += 5
        end
      end
      r.success
    end

    def scan_status(param)
      r = execute(make_xml('ScanStatusRequest', {'scan-id' => param}))
      r.success ? r.attributes['status'] : nil
    end

    #----------------------------------------------------------------
    # Resumes a scan.
    #
    # @param scan_id The scan ID.
    # @return Success(0|1) if it exists or null.
    #----------------------------------------------------------------
    def scan_resume(scan_id)
      r = execute(make_xml('ScanResumeRequest', {'scan-id' => scan_id}))
      r.success ? r.attributes['success'] : nil
    end


    #----------------------------------------------------------------
    # Pauses a scan.
    #
    # @param scan_id The scan ID.
    # @return Success(0|1) if it exists or null.
    #----------------------------------------------------------------
    def scan_pause(scan_id)
      r = execute(make_xml('ScanPauseRequest',{ 'scan-id' => scan_id}))
      r.success ? r.attributes['success'] : nil
    end

    # Retrieve a list of current scan activities across all Scan Engines managed
    # by Nexpose.
    #
    # @return [Array[ScanSummary]] Array of ScanSummary objects associated with
    #   each active scan on the engines.
    #
    def scan_activity
      r = execute(make_xml('ScanActivityRequest', {}))
      res = []
      if (r.success)
        r.res.elements.each("//ScanSummary") do |scan|
          res << ScanSummary.parse(scan)
        end
      end
      res
    end

    # Get scan statistics, including node and vulnerability breakdowns.
    #
    # @return [ScanSummary] ScanSummary object providing statistics for the scan.
    #
    def scan_statistics(scan_id)
      r = execute(make_xml('ScanStatisticsRequest', {'scan-id' => scan_id}))
      if r.success
        ScanSummary.parse(r.res.elements['//ScanSummary'])
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
    # The site that was scanned.
    attr_reader :site_id
    # The Engine ID the scan was dispatched to.
    attr_reader :engine_id
    # The scan start time
    attr_reader :start_time
    # The scan finish time
    attr_reader :end_time
    # The scan status.
    # One of: running|finished|stopped|error|dispatched|paused|aborted|uknown
    attr_reader :status

    # The reason the scan was stopped or failed, if applicable.
    attr_reader :message

    # Task statistics, including pending, active, and completed tasks.
    attr_reader :tasks
    # Node statistics, including live, dead, filtered, and unresolved.
    attr_reader :nodes
    # Vulnerability statistics, including statuses, severities, and counts.
    attr_reader :vulnerabilities

    # Constructor
    def initialize(scan_id, site_id, engine_id, status, start_time, end_time, message, tasks, nodes, vulnerabilities)
      @scan_id, @site_id, @engine_id, @status, @start_time, @end_time = scan_id, site_id, engine_id, status, start_time, end_time
      @message, @tasks, @nodes, @vulnerabilities = message, tasks, nodes, vulnerabilities
    end

    # Parse a response from a Nexpose console into a valid ScanSummary object.
    #
    # @param [REXML::Document] rexml XML document to parse.
    # @return [ScanSummary] Scan summary represented by the XML.
    #
    def self.parse(rexml)
      tasks = Tasks.parse(rexml.elements['tasks'])
      nodes = Nodes.parse(rexml.elements['nodes'])
      vulns = Vulnerabilities.parse(rexml.attributes['scan-id'], rexml)
      msg = rexml.elements['message'] ?  rexml.elements['message'].text : nil

      # Start time can be empty in some error conditions.
      start_time = nil
      unless rexml.attributes['startTime'] == ''
        start_time = DateTime.parse(rexml.attributes['startTime'].to_s).to_time
      end

      # End time is often not present, since reporting on running scans.
      end_time = nil
      if rexml.attributes['endTime']
        end_time = DateTime.parse(rexml.attributes['endTime'].to_s).to_time
      end
      return ScanSummary.new(rexml.attributes['scan-id'].to_i,
                             rexml.attributes['site-id'].to_i,
                             rexml.attributes['engine-id'].to_i,
                             rexml.attributes['status'], 
                             start_time,
                             end_time,
                             msg,
                             tasks,
                             nodes,
                             vulns)
    end

    # Value class to tracking task counts.
    #
    class Tasks
      attr_reader :pending, :active, :completed

      def initialize(pending, active, completed)
        @pending, @active, @completed = pending, active, completed
      end

      # Parse REXML to Tasks object.
      #
      # @param [REXML::Document] rexml XML document to parse.
      # @return [Tasks] Task summary represented by the XML.
      #
      def self.parse(rexml)
        return nil unless rexml
        return Tasks.new(rexml.attributes['pending'].to_i,
                         rexml.attributes['active'].to_i,
                         rexml.attributes['completed'].to_i)
      end
    end

    # Value class for tracking node counts.
    #
    class Nodes
      attr_reader :live, :dead, :filtered, :unresolved, :other

      def initialize(live, dead, filtered, unresolved, other)
        @live, @dead, @filtered, @unresolved, @other = live, dead, filtered, unresolved, other
      end

      # Parse REXML to Nodes object.
      #
      # @param [REXML::Document] rexml XML document to parse.
      # @return [Nodes] Node summary represented by the XML.
      #
      def self.parse(rexml)
        return nil unless rexml
        return Nodes.new(rexml.attributes['live'].to_i,
                         rexml.attributes['dead'].to_i,
                         rexml.attributes['filtered'].to_i,
                         rexml.attributes['unresolved'].to_i,
                         rexml.attributes['other'].to_i)
      end
    end

    # Value class for tracking vulnerability counts.
    #
    class Vulnerabilities
      attr_reader :vuln_exploit, :vuln_version, :vuln_potential,
        :not_vuln_exploit, :not_vuln_version,
        :error, :disabled, :other

      def initialize(vuln_exploit, vuln_version, vuln_potential,
                     not_vuln_exploit, not_vuln_version,
                     error, disabled, other)
        @vuln_exploit, @vuln_version, @vuln_potential,
          @not_vuln_exploit, @not_vuln_version,
          @error, @disabled, @other =
          vuln_exploit, vuln_version, vuln_potential,
          not_vuln_exploit, not_vuln_version,
          error, disabled, other
      end
      
      # Parse REXML to Vulnerabilities object.
      #
      # @param [FixNum] scan_id Scan ID to collect vulnerability data for.
      # @param [REXML::Document] rexml XML document to parse.
      # @return [Vulnerabilities] Vulnerability summary represented by the XML.
      #
      def self.parse(scan_id, rexml)
        return nil unless rexml
        map = {}
        rexml.elements.each("//ScanSummary[contains(@scan-id,'#{scan_id}')]/vulnerabilities") do |vuln|
          status = map[vuln.attributes['status']]
          if status && vuln.attributes['status'] =~ /^vuln-/
            status.add_severity(vuln.attributes['severity'].to_i, vuln.attributes['count'].to_i)
          else
            map[vuln.attributes['status']] = Status.new(vuln.attributes['severity'], vuln.attributes['count'].to_i)
          end
        end
        Vulnerabilities.new(map['vuln-exploit'],
                            map['vuln-version'],
                            map['vuln-potential'],
                            map['not-vuln-exploit'],
                            map['not-vuln-version'],
                            map['error'],
                            map['disabled'],
                            map['other'])
      end

      # Value class for tracking vulnerability status counts.
      #
      # Severities will only be mapped if they are provided in the response,
      # which currently only happens for vuln-exploit, vuln-version,
      # and vuln-potential.
      #
      class Status
        attr_reader :severities, :count

        def initialize(severity = nil, count = 0)
          if severity
            @severities = {}
            @count = 0
            add_severity(severity.to_i, count)
          else
            @severities = nil
            @count = count
          end
        end

        # For vuln-exploit, vuln-version, and vuln-potential,
        # map the count at a severity level, but also maintain an overall count.
        def add_severity(severity, count)
          @count += count
          @severities[severity] = count
        end
      end
    end
  end

  # TODO add engineID
  # === Description
  # Object that represents the scanning configuration for a Site.
  #
  class ScanConfig

    def self.parse(xml)
      config = ScanConfig.new(xml.attributes['configID'],
                              xml.attributes['name'],
                              xml.attributes['templateID'],
                              xml.attributes['configVersion'],
                              xml.attributes['engineID'])
      xml.elements.each('Schedules/Schedule') do |sched|
        schedule = Schedule.new(sched.attributes['type'],
                                sched.attributes['interval'],
                                sched.attributes['start'],
                                sched.attributes['enabled'])
        config.addSchedule(schedule)
      end
      config
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

    def initialize(scan_stop, scan_failed, scan_start)
      @scanStop = scan_stop
      @scanFailed = scan_failed
      @scanStart = scan_start
    end
  end
end
