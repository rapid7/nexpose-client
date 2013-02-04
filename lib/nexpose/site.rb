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
          res << {
            :device_id => device.attributes['id'].to_i,
            # TODO Covert to using?
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

    # Retrieve a list of all previous scans of the site.
    #
    # @param [FixNum] site_id Site ID to request scan history for.
    # @return [Array[ScanSummary]] Array of ScanSummary objects representing
    #   each scan run to date on the site provided.
    #
    def site_scan_history(site_id)
      r = execute(make_xml('SiteScanHistoryRequest', {'site-id' => site_id}))
      res = []
      if r.success
        r.res.elements.each("//ScanSummary") do |scan_event|
          res << ScanSummary.parse(scan_event)
        end
      end
      res
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

  # Configuration object representing a Nexpose site.
  #
  # For a basic walk-through, see {https://github.com/rapid7/nexpose-client/wiki/Using-Sites}
  class Site

    # The site ID. An ID of -1 is used to designate a site that has not been
    # saved to a Nexpose console.
    attr_accessor :id

    # Unique name of the site. Required.
    attr_accessor :name

    # Description of the site.
    attr_accessor :description

    # [Array] Collection of assets. May be IPv4, IPv6, or DNS names.
    # @see HostName
    # @see IPRange
    attr_accessor :assets

    # Scan template to use when starting a scan job. Default: full-audit
    attr_accessor :scan_template

    # Friendly name of scan template to use when starting a scan job.
    # Value is populated when a site is saved or loaded from a console.
    attr_accessor :scan_template_name

    # Scan Engine to use. Will use the default engine if nil or -1.
    attr_accessor :engine

    # [Array] Schedule starting dates and times for scans, and set their frequency.
    attr_accessor :schedules

    # The risk factor associated with this site. Default: 1.0
    attr_accessor :risk_factor

    # [Array] Collection of credentials associated with this site.
    attr_accessor :credentials

    # [Array] Collection of real-time alerts.
    # @see SMTPAlert
    # @see SNMPAlert
    # @see SyslogAlert
    attr_accessor :alerts

    # Configuration version. Default: 3
    attr_accessor :config_version

    # Whether or not this site is dynamic.
    # Dynamic sites are created through Asset Discovery Connections.
    # Modifying their behavior through the API is not recommended.
    attr_accessor :is_dynamic

    # Site constructor. Both arguments are optional.
    #
    # @param [String] name Unique name of the site.
    # @param [String] scan_template ID of the scan template to use.
    def initialize(name = nil, scan_template = 'full-audit')
      @name = name;
      @scan_template = scan_template

      @id = -1
      @risk_factor = 1.0
      @config_version = 3
      @is_dynamic = false
      @assets = []
      @schedules = []
      @credentials = []
      @alerts = []
    end

    # Returns true when the site is dynamic.
    def dynamic?
      is_dynamic
    end

    # Load an existing configuration from a Nexpose instance.
    #
    # @param [Connection] connection Connection to console where scan will be launched.
    # @param [Fixnum] id Site ID of an existing site.
    # @return [Site] Site configuration loaded from a Nexpose console.
    def self.load(connection, id)
      r = APIRequest.execute(connection.url, %Q(<SiteConfigRequest session-id="#{connection.session_id}" site-id="#{id}"/>))
      parse(r.res)
    end

    # Copy an existing configuration from a Nexpose instance.
    #
    # @param [Connection] connection Connection to console where scan will be launched.
    # @param [Fixnum] id Site ID of an existing site.
    # @return [Site] Site configuration loaded from a Nexpose console.
    def self.copy(connection, id)
      site = self.load(connection, id)
      site.id = -1
      site.name = "#{site.name} Copy"
      site
    end

    # Saves this site to a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this site will be saved.
    # @return [Fixnum] Site ID assigned to this configuration, if successful.
    def save(connection)
      r = connection.execute('<SiteSaveRequest session-id="' + connection.session_id + '">' + to_xml + ' </SiteSaveRequest>')
      if (r.success)
        @id = r.attributes['site-id']
        return @id
      end
    end

    # Delete this site from a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this site will be saved.
    # @return [Boolean] Whether or not the site was successfully deleted.
    def delete(connection)
      r = connection.execute(%Q{<SiteDeleteRequest session-id="#{connection.session_id}" site-id="#@id"/>})
      r.success
    end

    # Scan this site.
    #
    # @param [Connection] connection Connection to console where scan will be launched.
    # @param [String] sync_id Optional syncronization token.
    # @return [Fixnum, Fixnum] Scan ID and engine ID where the scan was launched.
    def scan(connection, sync_id = nil)
      xml = REXML::Element.new('SiteScanRequest')
      xml.add_attributes({'session-id' => connection.session_id,
                          'site-id' => id,
                          'sync-id' => sync_id})

      response = connection.execute(xml)
      if response.success
        response.res.elements.each('/SiteScanResponse/Scan/') do |scan|
          return [scan.attributes['scan-id'].to_i, scan.attributes['engine-id'].to_i]
        end
      end
    end

    # Generate an XML representation of this site configuration
    # @return [String] XML valid for submission as part of other requests.
    def to_xml
      xml = %Q(<Site id='#{id}' name='#{name}' description='#{description}' riskfactor='#{risk_factor}'>)

      xml << '<Hosts>'
      xml << assets.reduce('') { |acc, host| acc << host.to_xml }
      xml << '</Hosts>'

      unless credentials.empty?
        xml << '<Credentials>'
        credentials.each do |c|
          xml << c.to_xml if c.respond_to? :to_xml
        end
        xml << '</Credentials>'
      end

      unless alerts.empty?
        xml << '<Alerting>'
        alerts.each do |a|
          xml << a.to_xml if a.respond_to? :to_xml
        end
        xml << '</Alerting>'
      end

      xml << %Q(<ScanConfig configID="#{@id}" name="#{@scan_template_name || @scan_template}" templateID="#{@scan_template}" configVersion="#{@config_version || 3}" engineID="#{@engine}">)

      xml << '<Schedules>'
      @schedules.each do |sched|
        xml << %Q{<Schedule enabled="#{sched.enabled ? 1 : 0}" type="#{sched.type}" interval="#{sched.interval}" start="#{sched.start}" />}
      end
      xml << '</Schedules>'
      xml << '</ScanConfig>'
      xml << '</Site>'
    end

    # Parse a response from a Nexpose console into a valid Site object.
    #
    # @param [REXML::Document] rexml XML document to parse.
    # @return [Site] Site object represented by the XML.
    #  ## TODO What is returned on failure?
    def self.parse(rexml)
      rexml.elements.each('SiteConfigResponse/Site') do |s|
        site = Site.new(s.attributes['name'])
        site.id = s.attributes['id'].to_i
        site.description = s.attributes['description']
        site.risk_factor = s.attributes['riskfactor'] || 1.0
        site.is_dynamic = true if s.attributes['isDynamic'] == '1'

        s.elements.each('Hosts/range') do |r|
          site.assets << IPRange.new(r.attributes['from'], r.attributes['to'])
        end
        s.elements.each('Hosts/host') do |host|
          site.assets << HostName.new(host.text)
        end

        s.elements.each('ScanConfig') do |scan_config|
          site.scan_template_name = scan_config.attributes['name']
          site.scan_template = scan_config.attributes['templateID']
          site.config_version = scan_config.attributes['configVersion'].to_i
          site.engine = scan_config.attributes['engineID'].to_i
          scan_config.elements.each('Schedules/Schedule') do |sched|
            schedule = Schedule.new(sched.attributes['type'],
                                    sched.attributes['interval'],
                                    sched.attributes['start'],
                                    sched.attributes['enabled'])
            site.schedules << schedule
          end
        end

        s.elements.each('Credentials') do |cred|
          # TODO
        end

        s.elements.each('Alerting/Alert') do |a|
          a.elements.each('smtpAlert') do |smtp|
            smtp_alert = SMTPAlert.new(a.attributes['name'], smtp.attributes['sender'], smtp.attributes['limitText'], a.attributes['enabled'])

            smtp.elements.each('recipient') do |recipient|
              smtp_alert.addRecipient(recipient.text)
            end
            site.alerts << smtp_alert
          end

          a.elements.each('snmpAlert') do |snmp|
            snmp_alert = SNMPAlert.new(a.attributes['name'], snmp.attributes['community'], snmp.attributes['server'], a.attributes['enabled'])
            site.alerts << snmp_alert
          end

          a.elements.each('syslogAlert') do |syslog|
            syslog_alert = SyslogAlert.new(a.attributes['name'], syslog.attributes['server'], a.attributes['enabled'])
            site.alerts << syslog_alert
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

        return site
      end
      nil
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
  class SNMPAlert
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
  class SMTPAlert
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
