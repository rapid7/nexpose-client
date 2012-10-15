module Nexpose
  module NexposeAPI
    include XMLUtils

    #
    #
    #
    def site_device_listing(site_id)
      r = execute(make_xml('SiteDeviceListingRequest', {'site-id' => site_id.to_s}))

      if (r.success)
        res = []
        r.res.elements.each("//device") do |device|
          puts device
          res << {
            :device_id => device.attributes['id'].to_i,
            # TODO Covert to using?
            #   require 'ipaddr'
            #   :address => IPAddr.new(device.attributes['address']),
            :address => device.attributes['address'].to_s,
            :risk_factor => device.attributes['riskfactor'].to_f,
            :risk_score => device.attributes['riskscore'].to_f,
          }
        end
        res
      else
        false
      end
    end

    #
    #
    #
    def site_delete(param)
      r = execute(make_xml('SiteDeleteRequest', {'site-id' => param}))
      r.success
    end

    #
    #
    # TODO Should just return empty array if doesn't work?
    def site_listing
      r = execute(make_xml('SiteListingRequest', {}))

      if (r.success)
        res = []
        r.res.elements.each("//SiteSummary") do |site|
          res << {
            :site_id => site.attributes['id'].to_i,
            :name => site.attributes['name'].to_s,
            :risk_factor => site.attributes['riskfactor'].to_f,
            :risk_score => site.attributes['riskscore'].to_f,
          }
        end
        res
      else
        false
      end
    end

    #-----------------------------------------------------------------------
    # TODO: Needs to be expanded to included details
    #       Also confusing. Name clashes with field on Site
    #-----------------------------------------------------------------------
    def site_scan_history(site_id)
      r = execute(make_xml('SiteScanHistoryRequest', {'site-id' => site_id.to_s}))

      if (r.success)
        res = []
        r.res.elements.each("//ScanSummary") do |site_scan_history|
          res << {
            :site_id => site_scan_history.attributes['site-id'].to_i,
            :scan_id => site_scan_history.attributes['scan-id'].to_i,
            :engine_id => site_scan_history.attributes['engine-id'].to_i,
            :start_time => site_scan_history.attributes['startTime'].to_s,
            :end_time => site_scan_history.attributes['endTime'].to_s
          }
        end
        res
      else
        false
      end
    end

    #-----------------------------------------------------------------------
    # Starts device specific site scanning.
    #
    # devices - An Array of device IDs
    # hosts - An Array of Hashes [o]=>{:range=>"to,from"} [1]=>{:host=>host}
    #-----------------------------------------------------------------------
    def site_device_scan_start(site_id, devices, hosts)

      if hosts == nil and devices == nil
        raise ArgumentError.new("Both the device and host list is nil")
      end

      xml = make_xml('SiteDevicesScanRequest', {'site-id' => site_id})

      if devices != nil
        inner_xml = REXML::Element.new 'Devices'
        for device_id in devices
          inner_xml.add_element 'device', {'id' => "#{device_id}"}
        end
        xml.add_element inner_xml
      end

      if hosts
        inner_xml = REXML::Element.new 'Hosts'
        hosts.each_index do |x|
          if hosts[x].key? :range
            to = hosts[x][:range].split(',')[0]
            from = hosts[x][:range].split(',')[1]
            inner_xml.add_element 'range', {'to' => "#{to}", 'from' => "#{from}"}
          end
          if hosts[x].key? :host
            host_element = REXML::Element.new 'host'
            host_element.text = "#{hosts[x][:host]}"
            inner_xml.add_element host_element
          end
        end
        xml.add_element inner_xml
      end

      r = execute xml
      if r.success
        r.res.elements.each('//Scan') do |scan_info|
          return {
            :scan_id => scan_info.attributes['scan-id'].to_i,
            :engine_id => scan_info.attributes['engine-id'].to_i
          }
        end
      else
        false
      end
    end
  end

  #-------------------------------------------------------------------------------------------------------------------
  # === Description
  # Object that represents a site, including the site configuration, scan history, and device listing.
  #
  # === Example
  #   # Create a new Nexpose Connection on the default port and Login
  #   nsc = Connection.new("10.1.40.10","nxadmin","password")
  #   nsc.login()
  #
  #   # Get an Existing Site
  #   site_existing = Site.new(nsc,184)
  #
  #   # Create a New Site, add some hosts, and save it to the NSC
  #   site = Site.new(nsc)
  #   site.setSiteConfig("New Site", "New Site Created in the API")
  #
  #   # Add the hosts
  #   site.hosts << HostName.new('localhost')
  #   site.hosts << IPRange.new('192.168.7.1', '192.168.7.255')
  #   site.hosts << IPRange.new('10.1.20.30')
  #
  #   status = site.saveSite()
  #-------------------------------------------------------------------------------------------------------------------
  class Site
    # true if an error condition exists; false otherwise
    attr_reader :error
    # Error message string
    attr_reader :error_msg
    # The last XML request sent by this object
    attr_reader :request_xml
    # The last XML response received by this object
    attr_reader :response_xml
    # The NSC Connection associated with this object
    attr_reader :connection
    # The Site ID
    # site_id = -1 means create a new site. The NSC will assign a new site_id on SiteSave.
    attr_reader :site_id
    # A summary overview of this site
    # SiteSummary Object
    attr_reader :site_summary
    # The configuration of this site
    # SiteConfig Object
    attr_reader :site_config
    # The device listing for this site
    # SiteDeviceListing Object
    attr_reader :site_device_listing
    # The scan history of this site
    # SiteScanHistory Object
    attr_reader :site_scan_history

    def initialize(connection = nil, site_id = -1)
      @error = false
      @connection = connection
      @site_id = site_id

      # If site_id > 0 then retrieve site configuration from security console.
      if (@site_id.to_i > 0)
        # Create new SiteConfig object
        @site_config = SiteConfig.new()
        # Populate SiteConfig Obect with Data from the NSC
        @site_config.getSiteConfig(@connection, @site_id)
        @site_summary = SiteSummary.new(@site_id, @site_config.site_name, @site_config.description, @site_config.riskfactor)
        @site_scan_history = SiteScanHistory.new(@connection, @site_id)
        @site_device_listing = SiteDeviceListing.new(@connection, @site_id)

      else
        # Just in case user enters a number > -1 or = 0
        @site_id = -1

        @site_config = SiteConfig.new()
        # setSiteConfig("New Site " + rand(999999999999).to_s, "")
        @site_summary = nil

      end
    end

    # Unique identifier for this site.
    def id
      @site_config.id
    end

    # Set the ID for this site. -1 indicates that this configuration will be
    # saved as a new site when saved.
    def id=(value)
      @site_config.id = value
    end

    # The name of this site.
    def name
      @site_config.name
    end

    # Set the name of this site.
    def name=(value)
      @site_config.name = value
    end

    # A description of this site configuration.
    def description
      @site_config.description
    end

    # Set the description for this site.
    def description=(value)
      @site_config.description = value
    end

    # The risk factor associated with assets on this site.
    def risk_factor
      @site_config.riskfactor
    end

    # Set the risk factor for this site.
    def risk_factor=(value)
      @site_config.riskfactor = value
    end

    # The hosts (IPRange or HostName) associated with this site.
    def hosts
      @site_config.hosts
    end

    # Set the hosts array with user provided value.
    def hosts=(value)
      @site_config.hosts = value
    end

    # Add the host to the existing lists of hosts for this site.
    def add_host(host)
      @site_config.hosts << host
    end

    # Set the host for this site to the value supplied, overriding any previous
    # values.
    def set_host(host)
      @site_config.hosts = [host]
    end

    # Credentials to be used when scanning this site.
    def credentials
      @site_config.credentials
    end

    # Creates a new site summary
    def setSiteSummary(site_name, description, riskfactor = 1.0)
      @site_summary = SiteSummary.new(-1, site_name, description, riskfactor)

    end

    # Creates a new site configuration
    def setSiteConfig(site_name, description, riskfactor = 1.0)
      setSiteSummary(site_name, description, riskfactor)
      @site_config = SiteConfig.new()
      @site_config._set_site_id(-1)
      @site_config._set_site_name(site_name)
      @site_config._set_description(description)
      @site_config._set_riskfactor(riskfactor)
      @site_config._set_scanConfig(ScanConfig.new(-1, "tmp", "full-audit"))
      @site_config._set_connection(@connection)

    end

    # Scan this site.
    def scan(connection, sync_id = nil)
      xml = REXML::Element.new('SiteScanRequest')
      xml.add_attributes({'session-id' => connection.session_id,
                          'site-id' => id,
                          'sync-id' => sync_id})

      response = connection.execute(xml)
      if response.success
        response.res.elements.each('/SiteScanResponse/Scan/') do |scan|
          return [scan.attributes['scan-id'], scan.attributes['engine-id']]
        end
      end
    end

    # Initiates a scan of this site. If successful returns scan_id and engine_id in an associative array. Returns false if scan is unsuccessful.
    def scanSite()
      r = @connection.execute('<SiteScanRequest session-id="' + "#{@connection.session_id}" + '" site-id="' + "#{@site_id}" + '"/>')
      if (r.success)
        res = {}
        r.res.elements.each('//Scan/') do |s|
          res[:scan_id] = s.attributes['scan-id']
          res[:engine_id] = s.attributes['engine-id']
        end
        return res
      else
        return false
      end
    end

    # Saves this site in the NSC
    def saveSite
      r = @connection.execute('<SiteSaveRequest session-id="' + @connection.session_id + '">' + getSiteXML + ' </SiteSaveRequest>')
      if (r.success)
        @site_id = r.attributes['site-id']
        @site_config._set_site_id(@site_id)
        @site_config.scanConfig._set_configID(@site_id)
        @site_config.scanConfig._set_name(@site_id)
        return true
      else
        return false
      end
    end

    def deleteSite
      r = @connection.execute('<SiteDeleteRequest session-id="' + @connection.session_id.to_s + '" site-id="' + @site_id + '"/>')
      r.success
    end


    def printSite
      puts "Site ID: " + @site_summary.id
      puts "Site Name: " + @site_summary.site_name
      puts "Site Description: " + @site_summary.description
      puts "Site Risk Factor: " + @site_summary.riskfactor
    end

    def to_xml_elem
      xml = REXML::Element.new('Site')
      xml.add_attributes({'id' => id,
                          'name' => name,
                          'description' => description,
                          'riskfactor' => risk_factor})

      host_xml = REXML::Element.new('Hosts', xml)
      hosts.each { |host| host_xml.add_element(host.to_xml_elem) }

      unless credentials.empty?
        cred_xml = REXML::Element.new('Credentials', xml)
        credentials.each { |cred| cred_xml.add_element(cred.to_xml_elem) }
      end

      # TODO
      xml
    end

    def getSiteXML

      xml = %Q(<Site id='#{id}' name='#{name}' description='#{description}' riskfactor='#{risk_factor}'>)

      xml << '<Hosts>'
      xml << hosts.reduce('') { |acc, host| acc << host.to_xml }
      xml << '</Hosts>'

      unless credentials.empty?
        xml << '<Credentials>'
        credentials.each do |c|
          xml << c.to_xml if c.respond_to? :to_xml
        end
        xml << ' </Credentials>'
      end

      unless @site_config.alerts.empty?
        xml << ' <Alerting>'
        @site_config.alerts.each do |a|
          xml << a.to_xml if a.respond_to? :to_xml
        end
        xml << ' </Alerting>'
      end

      xml << %Q{<ScanConfig configID="#{@site_config.scanConfig.configID}" name="#{@site_config.scanConfig.name}" templateID="#{@site_config.scanConfig.templateID}" configVersion="#{@site_config.scanConfig.configVersion}" engineID="#{@site_config.scanConfig.engine_id}">}

      xml << ' <Schedules>'
      @site_config.scanConfig.schedules.each do |s|
        xml << %Q{<Schedule enabled="#{s.enabled ? 1 : 0}" type="#{s.type}" interval="#{s.interval}" start="#{s.start}" />}
      end
      xml << ' </Schedules>'

      unless @site_config.scanConfig.scanTriggers.empty?
        xml << ' <ScanTriggers>'
        @site_config.scanConfig.scanTriggers.each do |s|
          if (s.class.to_s == "Nexpose::AutoUpdate")
            xml << ' <autoUpdate enabled="' + s.enabled + '" incremental="' + s.incremental + '"/>'
          end
        end
        xml << ' </ScanTriggers>'
      end

      xml << ' </ScanConfig>'

      xml << ' </Site>'

      xml
    end
  end

  # === Description
  # Object that represents a listing of all of the sites available on an NSC.
  #
  # === Example
  #   # Create a new Nexpose Connection on the default port and Login
  #   nsc = Connection.new("10.1.40.10","nxadmin","password")
  #   nsc->login;
  #
  #   # Get Site Listing
  #   sitelisting = SiteListing.new(nsc)
  #
  #   # Enumerate through all of the SiteSummaries
  #   sitelisting.sites.each do |sitesummary|
  #       # Do some operation on each site
  #   end
  #
  class SiteListing
    # true if an error condition exists; false otherwise
    attr_reader :error
    # Error message string
    attr_reader :error_msg
    # The last XML request sent by this object
    attr_reader :request_xml
    # The last XML response received by this object
    attr_reader :response_xml
    # The NSC Connection associated with this object
    attr_reader :connection
    # Array containing SiteSummary objects for each site in the connection
    attr_reader :sites
    # The number of sites
    attr_reader :site_count

    # Constructor
    # SiteListing (connection)
    def initialize(connection)
      @sites = []

      @connection = connection

      r = @connection.execute('<SiteListingRequest session-id="' + @connection.session_id.to_s + '"/>')

      if (r.success)
        parse(r.res)
      else
        raise APIError.new(r, "Failed to get site listing")
      end
    end

    def parse(r)
      r.elements.each('SiteListingResponse/SiteSummary') do |s|
        site_summary = SiteSummary.new(
          s.attributes['id'].to_s,
          s.attributes['name'].to_s,
          s.attributes['description'].to_s,
          s.attributes['riskfactor'].to_s
        )
        @sites.push(site_summary)
      end
      @site_count = @sites.length
    end
  end

  # === Description
  # Object that represents the summary of a Nexpose Site.
  #
  class SiteSummary
    # The Site ID
    attr_reader :id
    # The Site Name
    attr_reader :site_name
    # A Description of the Site
    attr_reader :description
    # User assigned risk multiplier
    attr_reader :riskfactor

    # Constructor
    # SiteSummary(id, site_name, description, riskfactor = 1)
    def initialize(id, site_name, description, riskfactor = 1.0)
      @id = id
      @site_name = site_name
      @description = description
      @riskfactor = riskfactor
    end

    def _set_id(id)
      @id = id
    end
  end

  # === Description
  # Object that represents the configuration of a Site. This object is automatically created when a new Site object is instantiated.
  #
  class SiteConfig
    # true if an error condition exists; false otherwise
    attr_reader :error
    # Error message string
    attr_reader :error_msg
    # The last XML request sent by this object
    attr_reader :request_xml
    # The last XML response received by this object
    attr_reader :response_xml
    # The NSC Connection associated with this object
    attr_reader :connection
    # The Site ID
    attr_accessor :id
    attr_reader :site_id
    # The Site Name
    attr_accessor :name
    attr_reader :site_name
    # A Description of the Site
    attr_accessor :description
    # User assigned risk multiplier
    attr_accessor :riskfactor
    # Array containing ((IPRange|HostName)*)
    attr_accessor :hosts
    # Array containing (AdminCredentials*)
    attr_accessor :credentials
    # Array containing ((SmtpAlera|SnmpAlert|SyslogAlert)*)
    attr_accessor :alerts
    # ScanConfig object which holds Schedule and ScanTrigger Objects
    attr_accessor :scanConfig
    attr_reader :is_dynamic

    def initialize()
      @id = -1
      @xml_tag_stack = []
      @hosts = []
      @credentials = []
      @alerts = []
      @error = false
    end

    # Adds a new host to the hosts array
    def addHost(host)
      @hosts.push(host)
    end

    # Adds a new alert to the alerts array
    def addAlert(alert)
      @alerts.push(alert)
    end

    # Adds a new set of credentials to the credentials array
    def addCredentials(credential)
      @credentials.push(credential)
    end

    # TODO
    def getSiteConfig(connection, site_id)
      @connection = connection
      @id = @site_id = site_id

      r = APIRequest.execute(@connection.url, %Q(<SiteConfigRequest session-id="#{@connection.session_id}" site-id="#{@site_id}"/>))
      parse(r.res)
    end

    def self.get_site_config(connection, site_id)
      config = SiteConfig.new
      config.getSiteConfig(connection, site_id)
      config
    end

    def _set_site_id(site_id)
      @site_id = site_id
    end

    def _set_site_name(site_name)
      @site_name = site_name
    end

    def _set_description(description)
      @description = description
    end

    def _set_riskfactor(riskfactor)
      @riskfactor = riskfactor
    end

    def _set_scanConfig(scanConfig)
      @scanConfig = scanConfig
    end

    def _set_connection(connection)
      @connection = connection
    end

    def parse(response)
      response.elements.each('SiteConfigResponse/Site') do |s|
        @id = @site_id = s.attributes['id']
        @name = @site_name = s.attributes['name']
        @description = s.attributes['description']
        @riskfactor = s.attributes['riskfactor'] || 1.0
        @is_dynamic = s.attributes['isDynamic']
        s.elements.each('Hosts/range') do |r|
          @hosts.push(IPRange.new(r.attributes['from'], r.attributes['to']))
        end
        s.elements.each('Hosts/host') do |host|
          @hosts << HostName.new(host.text)
        end
        # TODO: This should just be passed to ScanConfig to parse.
        s.elements.each('ScanConfig') do |c|
          @scanConfig = ScanConfig.parse(c)
        end
        s.elements.each('Credentials') do |cred|
          # TODO
        end
        s.elements.each('Alerting/Alert') do |a|

          a.elements.each('smtpAlert') do |smtp|
            smtp_alert = SmtpAlert.new(a.attributes["name"], smtp.attributes["sender"], smtp.attributes["limitText"], a.attributes["enabled"])

            smtp.elements.each('recipient') do |recipient|
              smtp_alert.addRecipient(recipient.text)
            end
            @alerts.push(smtp_alert)
          end

          a.elements.each('snmpAlert') do |snmp|
            snmp_alert = SnmpAlert.new(a.attributes["name"], snmp.attributes["community"], snmp.attributes["server"], a.attributes["enabled"])
            @alerts.push(snmp_alert)
          end
          a.elements.each('syslogAlert') do |syslog|
            syslog_alert = SyslogAlert.new(a.attributes["name"], syslog.attributes["server"], a.attributes["enabled"])
            @alerts.push(syslog_alert)
          end

          a.elements.each('vulnFilter') do |vulnFilter|

            #vulnfilter = new VulnFilter.new(a.attributes["typemask"], a.attributes["severityThreshold"], $attrs["MAXALERTS"])
            # Pop off the top alert on the stack
            #$alert = @alerts.pop()
            # Add the new recipient string to the Alert Object
            #$alert.setVulnFilter($vulnfilter)
            # Push the alert back on to the alert stack
            #array_push($this->alerts, $alert)
          end

          a.elements.each('scanFilter') do |scanFilter|
            #<scanFilter scanStop='0' scanFailed='0' scanStart='1'/>
            #scanfilter = ScanFilter.new(scanFilter.attributes['scanStop'],scanFilter.attributes['scanFailed'],scanFilter.attributes['scanStart'])
            #alert = @alerts.pop()
            #alert.setScanFilter(scanfilter)
            #@alerts.push(alert)
          end
        end
      end
    end
  end

  # === Description
  # Object that represents the scan history of a site.
  #
  class SiteScanHistory
    # true if an error condition exists; false otherwise
    attr_reader :error
    # Error message string
    attr_reader :error_msg
    # The last XML request sent by this object
    attr_reader :request_xml
    # The last response received by this object
    attr_reader :response
    # The NSC Connection associated with this object
    attr_reader :connection
    # The Site ID
    attr_reader :site_id
    # //Array containing (ScanSummary*)
    attr_reader :scan_summaries

    def initialize(connection, id)
      @site_id = id
      @error = false
      @connection = connection
      @scan_summaries = []

      @request_xml = '<SiteScanHistoryRequest' + ' session-id="' + @connection.session_id + '" site-id="' + "#{@site_id}" + '"/>'
      r = @connection.execute(@request_xml)
      @response = r

      if r and r.success
        r.res.elements.each('//ScanSummary') do |summary|
          scan_id=summary.attributes['scan-id'].to_i
          engine_id=summary.attributes['engine-id'].to_i
          name=summary.attributes['name'].to_s
          start_time=summary.attributes['startTime'].to_s
          end_time=summary.attributes['endTime'].to_s
          status=summary.attributes['status'].to_s
          scan_summary = ScanSummary.new(scan_id, engine_id, name, start_time, end_time, status)
          scan_summaries << scan_summary
        end
      end
    end
  end

  # === Description
  # Object that represents a listing of devices for a site or the entire NSC. Note that only devices which are accessible to the account used to create the connection object will be returned. This object is created and populated automatically with the instantiation of a new Site object.
  #
  class SiteDeviceListing

    # true if an error condition exists; false otherwise
    attr_reader :error
    # Error message string
    attr_reader :error_msg
    # The last XML request sent by this object
    attr_reader :request_xml
    # The last XML response received by this object
    attr_reader :response_xml
    # The NSC Connection associated with this object
    attr_reader :connection
    # The Site ID. 0 if all sites are specified.
    attr_reader :site_id
    # //Array of (Device)*
    attr_reader :devices

    def initialize(connection, site_id = 0)

      @site_id = site_id
      @error = false
      @connection = connection
      @devices = []

      r = nil
      if (@site_id)
        r = @connection.execute('<SiteDeviceListingRequest session-id="' + connection.session_id + '" site-id="' + "#{@site_id}" + '"/>')
        if r.success
          r.res.elements.each('SiteDeviceListingResponse/SiteDevices/device') do |d|
            @devices.push(Device.new(d.attributes['id'], @site_id, d.attributes["address"], d.attributes["riskfactor"], d.attributes["riskscore"]))
          end
        end
      else
        r = @connection.execute('<SiteDeviceListingRequest session-id="' + connection.session_id + '"/>')
        if r.success
          r.res.elements.each('SiteDeviceListingResponse/SiteDevices') do |rr|
            @sid = rr.attribute("site-id")
            rr.elements.each('device') do |d|
              @devices.push(Device.new(d.attributes['id'], @sid, d.attributes["address"], d.attributes['riskfactor'], d.attributes['riskscore']))
            end
          end
        end
      end
    end
  end

  # === Description
  # Object that represents a single device in an NSC.
  #
  class Device

    # A unique device ID (assigned by the NSC)
    attr_reader :id
    # The site ID of this devices site
    attr_reader :site_id
    # IP Address or Hostname of this device
    attr_reader :address
    # User assigned risk multiplier
    attr_reader :riskfactor
    # Nexpose risk score
    attr_reader :riskscore

    def initialize(id, site_id, address, riskfactor=1, riskscore=0)
      @id = id
      @site_id = site_id
      @address = address
      @riskfactor = riskfactor
      @riskscore = riskscore

    end
  end

  # === Description
  # Object that represents a Syslog Alert.
  #
  class SyslogAlert

    # A unique name for this alert
    attr_reader :name
    # If this alert is enabled or not
    attr_reader :enabled
    # The Syslog server to sent this alert
    attr_reader :server
    # The vulnerability filter to trigger the alert
    attr_reader :vulnFilter
    # The alert type
    attr_reader :type

    def initialize(name, server, enabled = 1)
      @type = :syslog
      @name = name
      @server = server
      @enabled = enabled
      # Sets default vuln filter - All Events
      setVulnFilter(VulnFilter.new("50790400", 1))

    end

    # Sets the Vulnerability Filter for this alert.
    def setVulnFilter(vulnFilter)
      @vulnFilter = vulnFilter
    end

    include Sanitize

    def to_xml
      xml = "<syslogAlert"
      xml << %Q{ name="#{replace_entities(name)}"}
      xml << %Q{ enabled="#{replace_entities(enabled)}"}
      xml << %Q{ server="#{replace_entities(server)}">}
      xml << vulnFilter.to_xml
      xml << "</syslogAlert>"
      xml
    end

  end

  # === Description
  # Object that represents an SNMP Alert.
  #
  class SnmpAlert
    include Sanitize

    # A unique name for this alert
    attr_reader :name
    # If this alert is enabled or not
    attr_reader :enabled
    # The community string
    attr_reader :community
    # The SNMP server to sent this alert
    attr_reader :server
    # The vulnerability filter to trigger the alert
    attr_reader :vulnFilter
    # The alert type
    attr_reader :type

    def initialize(name, community, server, enabled = 1)
      @type = :snmp
      @name = name
      @community = community
      @server = server
      @enabled = enabled
      # Sets default vuln filter - All Events
      setVulnFilter(VulnFilter.new("50790400", 1))
    end

    # Sets the Vulnerability Filter for this alert.
    def setVulnFilter(vulnFilter)
      @vulnFilter = vulnFilter
    end

    def to_xml
      xml = "<snmpAlert"
      xml << %Q{ name="#{replace_entities(name)}"}
      xml << %Q{ enabled="#{replace_entities(enabled)}"}
      xml << %Q{ community="#{replace_entities(community)}"}
      xml << %Q{ server="#{replace_entities(server)}">}
      xml << vulnFilter.to_xml
      xml << "</snmpAlert>"
      xml
    end

  end

  # === Description
  # Object that represents an SMTP (Email) Alert.
  #
  class SmtpAlert
    # A unique name for this alert
    attr_reader :name
    # If this alert is enabled or not
    attr_reader :enabled
    # The email address of the sender
    attr_reader :sender
    # Limit the text for mobile devices
    attr_reader :limitText
    # Array containing Strings of email addresses
    # Array of strings with the email addresses of the intended recipients
    attr_reader :recipients
    # The vulnerability filter to trigger the alert
    attr_reader :vulnFilter
    # The alert type
    attr_reader :type

    def initialize(name, sender, limitText, enabled = 1)
      @type = :smtp
      @name = name
      @sender = sender
      @enabled = enabled
      @limitText = limitText
      @recipients = []
      # Sets default vuln filter - All Events
      setVulnFilter(VulnFilter.new("50790400", 1))
    end

    # Adds a new Recipient to the recipients array
    def addRecipient(recipient)
      @recipients.push(recipient)
    end

    # Sets the Vulnerability Filter for this alert.
    def setVulnFilter(vulnFilter)
      @vulnFilter = vulnFilter
    end

    include Sanitize

    def to_xml
      xml = "<smtpAlert"
      xml << %Q{ name="#{replace_entities(name)}"}
      xml << %Q{ enabled="#{replace_entities(enabled)}"}
      xml << %Q{ sender="#{replace_entities(sender)}"}
      xml << %Q{ limitText="#{replace_entities(limitText)}">}
      recipients.each do |recpt|
        xml << "<recipient>#{replace_entities(recpt)}</recipient>"
      end
      xml << vulnFilter.to_xml
      xml << "</smtpAlert>"
      xml
    end
  end

  # === Description
  # Object that represents a hostname to be added to a site.
  class HostName
    # Named host (usually DNS or Netbios name).
    attr_accessor :host

    def initialize(hostname)
      @host = hostname
    end

    include Comparable

    def <=>(other)
      to_xml <=> other.to_xml
    end

    def eql?(other)
      to_xml == other.to_xml
    end

    def hash
      to_xml.hash
    end

    def to_xml_elem
      xml = REXML::Element.new('host')
      xml.text = @host
      xml
    end

    def to_xml
      to_xml_elem.to_s
    end
  end

  # === Description
  # Object that represents a single IP address or an inclusive range of IP addresses.
  # If to is nil then the from field will be used to specify a single IP Address only.
  class IPRange
    require 'ipaddr'

    # Start of range *Required
    attr_accessor :from
    # End of range *Optional (If nil then IPRange is a single IP Address)
    attr_accessor :to

    def initialize(from, to = nil)
      @from = IPAddr.new(from)
      @to = IPAddr.new(to) if to
    end

    include Comparable

    def <=>(other)
      to_xml <=> other.to_xml
    end

    def eql?(other)
      to_xml == other.to_xml
    end

    def hash
      to_xml.hash
    end

    def to_xml_elem
      xml = REXML::Element.new('range')
      xml.add_attributes({'from' => @from, 'to' => @to})
      xml
    end

    def to_xml
      to_xml_elem.to_s
    end
  end
end
