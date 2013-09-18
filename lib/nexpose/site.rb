module Nexpose
  module NexposeAPI
    include XMLUtils

    # Retrieve a list of all sites the user is authorized to view or manage.
    #
    # @return [Array[SiteSummary]] Array of SiteSummary objects.
    #
    def list_sites
      r = execute(make_xml('SiteListingRequest'))
      arr = []
      if r.success
        r.res.elements.each('SiteListingResponse/SiteSummary') do |site|
          arr << SiteSummary.new(site.attributes['id'].to_i,
                                 site.attributes['name'],
                                 site.attributes['description'],
                                 site.attributes['riskfactor'].to_f,
                                 site.attributes['riskscore'].to_f)
        end
      end
      arr
    end

    alias_method :sites, :list_sites

    # Delete the specified site and all associated scan data.
    #
    # @return Whether or not the delete request succeeded.
    #
    def delete_site(site_id)
      r = execute(make_xml('SiteDeleteRequest', {'site-id' => site_id}))
      r.success
    end

    # Retrieve a list of all previous scans of the site.
    #
    # @param [FixNum] site_id Site ID to request scan history for.
    # @return [Array[ScanSummary]] Array of ScanSummary objects representing
    #   each scan run to date on the site provided.
    #
    def site_scan_history(site_id)
      r = execute(make_xml('SiteScanHistoryRequest', {'site-id' => site_id}))
      scans = []
      if r.success
        r.res.elements.each('SiteScanHistoryResponse/ScanSummary') do |scan_event|
          scans << ScanSummary.parse(scan_event)
        end
      end
      scans
    end

    # Retrieve the scan summary statistics for the latest completed scan
    # on a site.
    #
    # Method will not return data on an active scan.
    #
    # @param [FixNum] site_id Site ID to find latest scan for.
    # @return [ScanSummary] details of the last completed scan for a site.
    #
    def last_scan(site_id)
      site_scan_history(site_id).select { |scan| scan.end_time }.max_by { |scan| scan.end_time }
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

    # [Array] Collection of excluded assets. May be IPv4, IPv6, or DNS names.
    attr_accessor :exclude

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

    # [Array] Collection of credentials associated with this site. Does not
    # include shared credentials.
    attr_accessor :credentials

    # [Array] Collection of real-time alerts.
    # @see Alert
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
      @name = name
      @scan_template = scan_template

      @id = -1
      @risk_factor = 1.0
      @config_version = 3
      @is_dynamic = false
      @assets = []
      @schedules = []
      @credentials = []
      @alerts = []
      @exclude = []
    end

    # Returns true when the site is dynamic.
    def dynamic?
      is_dynamic
    end

    # Adds an asset to this site by host name.
    #
    # @param [String] hostname FQDN or DNS-resolvable host name of an asset.
    def add_host(hostname)
      @assets << HostName.new(hostname)
    end

    # Adds an asset to this site by IP address.
    #
    # @param [String] ip IP address of an asset.
    def add_ip(ip)
      @assets << IPRange.new(ip)
    end

    # Adds assets to this site by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def add_ip_range(from, to)
      @assets << IPRange.new(from, to)
    end

    # Adds an asset to this site, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def add_asset(asset)
      begin
        # If the asset registers as a valid IP, store as IP.
        ip = IPAddr.new(asset)
        add_ip(asset)
      rescue ArgumentError => e
        if e.message == 'invalid address'
          add_host(asset)
        else
          raise "Unable to parse asset: '#{asset}'. #{e.message}"
        end
      end
    end

    # Load an existing configuration from a Nexpose instance.
    #
    # @param [Connection] connection Connection to console where site exists.
    # @param [Fixnum] id Site ID of an existing site.
    # @return [Site] Site configuration loaded from a Nexpose console.
    #
    def self.load(connection, id)
      r = APIRequest.execute(connection.url,
                             %(<SiteConfigRequest session-id="#{connection.session_id}" site-id="#{id}"/>))
      parse(r.res)
    end

    # Copy an existing configuration from a Nexpose instance.
    # Returned object will reset the site ID and append "Copy" to the existing
    # name.
    #
    # @param [Connection] connection Connection to the security console.
    # @param [Fixnum] id Site ID of an existing site.
    # @return [Site] Site configuration loaded from a Nexpose console.
    #
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
    #
    def save(connection)
      r = connection.execute('<SiteSaveRequest session-id="' + connection.session_id + '">' + to_xml + ' </SiteSaveRequest>')
      @id = r.attributes['site-id'].to_i if r.success
    end

    # Delete this site from a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this site will be saved.
    # @return [Boolean] Whether or not the site was successfully deleted.
    #
    def delete(connection)
      r = connection.execute(%(<SiteDeleteRequest session-id="#{connection.session_id}" site-id="#{@id}"/>))
      r.success
    end

    # Scan this site.
    #
    # @param [Connection] connection Connection to console where scan will be launched.
    # @param [String] sync_id Optional synchronization token.
    # @return [Scan] Scan launch information.
    #
    def scan(connection, sync_id = nil)
      xml = REXML::Element.new('SiteScanRequest')
      xml.add_attributes({ 'session-id' => connection.session_id,
                           'site-id' => @id,
                           'sync-id' => sync_id })

      response = connection.execute(xml)
      Scan.parse(response.res) if response.success
    end

    include Sanitize

    # Generate an XML representation of this site configuration
    #
    # @return [String] XML valid for submission as part of other requests.
    #
    def to_xml
      xml = %(<Site id='#{id}' name='#{replace_entities(name)}' description='#{description}' riskfactor='#{risk_factor}'>)

      xml << '<Hosts>'
      xml << assets.reduce('') { |a, e| a << e.to_xml }
      xml << '</Hosts>'

      unless exclude.empty?
        xml << '<ExcludedHosts>'
        xml << exclude.reduce('') { |a, e| a << e.to_xml }
        xml << '</ExcludedHosts>'
      end

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

      xml << %(<ScanConfig configID="#{@id}" name="#{@scan_template_name || @scan_template}" templateID="#{@scan_template}" configVersion="#{@config_version || 3}" engineID="#{@engine}">)

      xml << '<Schedules>'
      @schedules.each do |schedule|
        xml << schedule.to_xml
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
    #
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

        s.elements.each('ExcludedHosts/range') do |r|
          site.exclude << IPRange.new(r.attributes['from'], r.attributes['to'])
        end
        s.elements.each('ExcludedHosts/host') do |host|
          site.exclude << HostName.new(host.text)
        end

        s.elements.each('Credentials/adminCredentials') do |cred|
          site.credentials << Credential.parse(cred)
        end

        s.elements.each('ScanConfig') do |scan_config|
          site.scan_template_name = scan_config.attributes['name']
          site.scan_template = scan_config.attributes['templateID']
          site.config_version = scan_config.attributes['configVersion'].to_i
          site.engine = scan_config.attributes['engineID'].to_i
          scan_config.elements.each('Schedules/Schedule') do |schedule|
            site.schedules << Schedule.parse(schedule)
          end
        end

        s.elements.each('Alerting/Alert') do |alert|
          site.alerts << Alert.parse(alert)
        end

        return site
      end
      nil
    end
  end

  # Object that represents the summary of a Nexpose Site.
  #
  class SiteSummary

    # The Site ID.
    attr_reader :id
    # The Site Name.
    attr_reader :name
    # A Description of the Site.
    attr_reader :description
    # User assigned risk multiplier.
    attr_reader :risk_factor
    # Current computed risk score for the site.
    attr_reader :risk_score

    # Constructor
    # SiteSummary(id, name, description, riskfactor = 1)
    def initialize(id, name, description = nil, risk_factor = 1.0, risk_score = 0.0)
      @id = id
      @name = name
      @description = description
      @risk_factor = risk_factor
      @risk_score = risk_score
    end
  end

  # Object that represents a hostname to be added to a site.
  #
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

  # Object that represents a single IP address or an inclusive range of IP addresses.
  # If to is nil then the from field will be used to specify a single IP Address only.
  #
  class IPRange

    # Start of range *Required
    attr_accessor :from
    # End of range *Optional (If nil then IPRange is a single IP Address)
    attr_accessor :to

    def initialize(from, to = nil)
      @from = from
      @to = to unless from == to
    end

    # Size of the IP range. The total number of IP addresses represented
    # by this range.
    #
    # @return [Fixnum] size of the range.
    #
    def size
      return 1 if @to.nil?
      from = IPAddr.new(@from)
      to = IPAddr.new(@to)
      (from..to).to_a.size
    end

    include Comparable

    def <=>(other)
      from = IPAddr.new(@from)
      to = @to.nil? ? from : IPAddr.new(@to)
      cf_from = IPAddr.new(other.from)
      cf_to = IPAddr.new(other.to.nil? ? other.from : other.to)
      if cf_to < from
        1
      elsif to < cf_from
        -1
      else # Overlapping
        0
      end
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      @from == other.from && @to == other.to
    end

    def include?(single_ip)
      from = IPAddr.new(@from)
      to = @to.nil? ? from : IPAddr.new(@to)
      other = IPAddr.new(single_ip)

      if other < from
        false
      elsif to < other
        false
      else
        true
      end
    end

    def hash
      to_xml.hash
    end

    def to_xml_elem
      xml = REXML::Element.new('range')
      xml.add_attributes({ 'from' => @from, 'to' => @to })
      xml
    end

    def to_xml
      to_xml_elem.to_s
    end
  end
end
