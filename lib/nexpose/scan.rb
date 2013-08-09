module Nexpose
  module NexposeAPI
    include XMLUtils

    # Perform an ad hoc scan of a single device.
    #
    # @param [Device] device Device to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_device(device)
      scan_devices([device])
    end

    # Perform an ad hoc scan of a subset of devices for a site.
    # Nexpose only allows devices from a single site to be submitted per
    # request.
    # Method is designed to take objects from a Device listing.
    #
    # For example:
    #   devices = nsc.devices(5)
    #   nsc.scan_devices(devices.take(10))
    #
    # @param [Array[Device]] devices List of devices to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_devices(devices)
      site_id = devices.map { |d| d.site_id }.uniq.first
      xml = make_xml('SiteDevicesScanRequest', {'site-id' => site_id})
      elem = REXML::Element.new('Devices')
      devices.each do |device|
        elem.add_element('device', {'id' => "#{device.id}"})
      end
      xml.add_element(elem)

      _scan_ad_hoc(xml)
    end

    # Perform an ad hoc scan of a single asset of a site.
    #
    # @param [Fixnum] site_id Site ID that the assets belong to.
    # @param [HostName|IPRange] asset Asset to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_asset(site_id, asset)
      scan_assets(site_id, [asset])
    end

    # Perform an ad hoc scan of a subset of assets for a site.
    # Only assets from a single site should be submitted per request.
    # Method is designed to take objects filtered from Site#assets.
    #
    # For example:
    #   site = Site.load(nsc, 5)
    #   nsc.scan_assets(5, site.assets.take(10))
    #
    # @param [Fixnum] site_id Site ID that the assets belong to.
    # @param [Array[HostName|IPRange]] assets List of assets to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_assets(site_id, assets)
      xml = make_xml('SiteDevicesScanRequest', {'site-id' => site_id})
      hosts = REXML::Element.new('Hosts')
      assets.each { |asset| _append_asset!(hosts, asset) }
      xml.add_element(hosts)

      _scan_ad_hoc(xml)
    end

    # Perform an ad hoc scan of a subset of IP addresses for a site.
    # Only IPs from a single site can be submitted per request,
    # and IP addresses must already be included in the site configuration.
    # Method is designed for scanning when the targets are coming from an
    # external source that does not have access to internal identfiers.
    #
    # For example:
    #   to_scan = ['192.168.2.1', '192.168.2.107']
    #   nsc.scan_ips(5, to_scan)
    #
    # @param [Fixnum] site_id Site ID that the assets belong to.
    # @param [Array[String]] ip_addresses Array of IP addresses to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_ips(site_id, ip_addresses)
      xml = make_xml('SiteDevicesScanRequest', {'site-id' => site_id})
      hosts = REXML::Element.new('Hosts')
      ip_addresses.each do |ip|
        xml.add_element('range', {'from' => ip})
      end
      xml.add_element(hosts)

      _scan_ad_hoc(xml)
    end

    # Initiate a site scan.
    #
    # @param [Fixnum] site_id Site ID to scan.
    # @return [Scan] Scan launch information.
    #
    def scan_site(site_id)
      xml = make_xml('SiteScanRequest', {'site-id' => site_id})
      response = execute(xml)
      Scan.parse(response.res) if response.success
    end

    # Utility method for appending a HostName or IPRange object into an
    # XML object, in preparation for ad hoc scanning.
    #
    # @param [REXML::Document] xml Prepared API call to execute.
    # @param [HostName|IPRange] asset Asset to append to XML.
    #
    def _append_asset!(xml, asset)
      if asset.kind_of? Nexpose::IPRange
        xml.add_element('range', {'from' => asset.from, 'to' => asset.to})
      else  # Assume HostName
        host = REXML::Element.new('host')
        host.text = asset.host
        xml.add_element(host)
      end
    end

    # Utility method for executing prepared XML and extracting Scan launch
    # information.
    #
    # @param [REXML::Document] xml Prepared API call to execute.
    # @return [Scan] Scan launch information.
    #
    def _scan_ad_hoc(xml)
      r = execute(xml)
      Scan.parse(r.res)
    end

    # Stop a running or paused scan.
    #
    # @param [Fixnum] scan_id ID of the scan to stop.
    # @param [Fixnum] wait_sec Number of seconds to wait for status to be
    #   updated.
    #
    def stop_scan(scan_id, wait_sec = 0)
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

    # Resumes a scan.
    #
    # @param [Fixnum] scan_id The scan ID.
    #
    def resume_scan(scan_id)
      r = execute(make_xml('ScanResumeRequest', {'scan-id' => scan_id}))
      r.success ? r.attributes['success'] : nil
    end


    # Pauses a scan.
    #
    # @param [Fixnum] scan_id The scan ID.
    #
    def pause_scan(scan_id)
      r = execute(make_xml('ScanPauseRequest', {'scan-id' => scan_id}))
      r.success ? r.attributes['success'] : nil
    end

    # Retrieve a list of current scan activities across all Scan Engines
    # managed by Nexpose.
    #
    # @return [Array[ScanSummary]] Array of ScanSummary objects associated with
    #   each active scan on the engines.
    #
    def scan_activity
      r = execute(make_xml('ScanActivityRequest'))
      res = []
      if r.success
        r.res.elements.each('//ScanSummary') do |scan|
          res << ScanSummary.parse(scan)
        end
      end
      res
    end

    # Get scan statistics, including node and vulnerability breakdowns.
    #
    # @param [Fixnum] scan_id Scan ID to retrieve statistics for.
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
    def self.parse(xml)
      tasks = Tasks.parse(xml.elements['tasks'])
      nodes = Nodes.parse(xml.elements['nodes'])
      vulns = Vulnerabilities.parse(xml.attributes['scan-id'], xml)
      msg = xml.elements['message'] ?  xml.elements['message'].text : nil

      # Start time can be empty in some error conditions.
      start_time = nil
      unless xml.attributes['startTime'] == ''
        start_time = DateTime.parse(xml.attributes['startTime'].to_s).to_time
      end

      # End time is often not present, since reporting on running scans.
      end_time = nil
      if xml.attributes['endTime']
        end_time = DateTime.parse(xml.attributes['endTime'].to_s).to_time
      end
      return ScanSummary.new(xml.attributes['scan-id'].to_i,
                             xml.attributes['site-id'].to_i,
                             xml.attributes['engine-id'].to_i,
                             xml.attributes['status'],
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

  # Struct class for tracking scan launch information.
  #
  class Scan

    # The scan ID when a scan is successfully launched.
    attr_reader :id
    # The engine the scan was dispatched to.
    attr_reader :engine

    def initialize(scan_id, engine_id)
      @id, @engine = scan_id, engine_id
    end

    def self.parse(xml)
      xml.elements.each('//Scan') do |scan|
        return new(scan.attributes['scan-id'].to_i,
                   scan.attributes['engine-id'].to_i)
      end
    end
  end
end
