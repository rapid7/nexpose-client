module Nexpose

  class Connection
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
      r = execute(make_xml('SiteDeleteRequest', { 'site-id' => site_id }))
      r.success
    end

    # Retrieve a list of all previous scans of the site.
    #
    # @param [FixNum] site_id Site ID to request scan history for.
    # @return [Array[ScanSummary]] Array of ScanSummary objects representing
    #   each scan run to date on the site provided.
    #
    def site_scan_history(site_id)
      r = execute(make_xml('SiteScanHistoryRequest', { 'site-id' => site_id }))
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
      site_scan_history(site_id).select(&:end_time).max_by(&:end_time)
    end

    # Retrieve a history of the completed scans for a given site.
    #
    # @param [FixNum] site_id Site ID to find scans for.
    # @return [CompletedScan] details of the completed scans for the site.
    #
    def completed_scans(site_id)
      table = { 'table-id' => 'site-completed-scans' }
      data = DataTable._get_json_table(self, "/data/scan/site/#{site_id}", table)
      data.map(&CompletedScan.method(:parse_json))
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

    # Information about the organization that this site belongs to.
    # Used by some reports.
    attr_accessor :organization

    # [Array] List of user IDs for users who have access to the site.
    attr_accessor :users

    # Configuration version. Default: 3
    attr_accessor :config_version

    # Whether or not this site is dynamic.
    # Dynamic sites are created through Asset Discovery Connections.
    attr_accessor :is_dynamic

    # Asset filter criteria if this site is dynamic.
    attr_accessor :criteria

    # ID of the discovery connection associated with this site if it is dynamic.
    attr_accessor :discovery_connection_id

    # [Array[TagSummary]] Collection of TagSummary
    attr_accessor :tags

    # Site constructor. Both arguments are optional.
    #
    # @param [String] name Unique name of the site.
    # @param [String] scan_template ID of the scan template to use.
    def initialize(name = nil, scan_template = 'full-audit-without-web-spider')
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
      @users = []
      @tags = []
    end

    # Returns true when the site is dynamic.
    def dynamic?
      is_dynamic
    end

    def discovery_connection_id=(value)
      @is_dynamic = true
      @discovery_connection_id = value.to_i
    end

    def include_asset?(asset)
      include_hostname?(asset) || include_ip_range?(asset)
    end

    def include_hostname?(host)
      host = HostName.new(host) unless host.is_a?(HostName)
      assets.grep(HostName) { |asset| asset.eql?(host) }.any?
    end

    def include_ip_range?(range)
      assets.grep(IPRange) { |asset| asset.include?(range) }.any?
    end

    # Adds an asset to this site by host name.
    #
    # @param [String] hostname FQDN or DNS-resolvable host name of an asset.
    def add_host(hostname)
      @assets << HostName.new(hostname)
    end

    # Remove an asset to this site by host name.
    #
    # @param [String] hostname FQDN or DNS-resolvable host name of an asset.
    def remove_host(hostname)
      @assets = assets.reject { |asset| asset == HostName.new(hostname) }
    end

    # Adds an asset to this site by IP address.
    #
    # @param [String] ip IP address of an asset.
    def add_ip(ip)
      @assets << IPRange.new(ip)
    end

    # Remove an asset to this site by IP address.
    #
    # @param [String] ip IP address of an asset.
    def remove_ip(ip)
      ip = IPRange.new(ip)
      @assets.each do |asset_range|
        return if asset_range.is_a?(Nexpose::HostName)
        if asset_range == ip
          @assets.delete(asset_range)
        elsif asset_range.include?(ip)
          asset = split_ip_range(asset_range, ip)
          @assets.delete(asset_range)
          @assets.push(asset)
          @assets.flatten!
        end
      end
    end

    def split_ip_range(ip_range, split_ip)
      split_ip = IPAddr.new(split_ip.from)
      start_ip, end_ip = IPAddr.new(ip_range.from), IPAddr.new(ip_range.to)
      all_ip_range = (start_ip..end_ip)

      case split_ip
      when all_ip_range.min
        new_start = IPAddr.new(start_ip.to_i + 1, start_ip.family).to_s
        asset = Nexpose::IPRange.new(new_start, ip_range.to)
      when all_ip_range.max
        new_end = IPAddr.new(end_ip.to_i - 1, end_ip.family).to_s
        asset = Nexpose::IPRange.new(ip_range.from, new_end)
      else
        asset = ip_range_split_calc(start_ip, end_ip, split_ip)
      end
      return asset
    end

    def ip_range_split_calc(start_ip, end_ip, split_ip)
      low_split  = IPAddr.new(split_ip.to_i - 1, start_ip.family).to_s
      high_split = IPAddr.new(split_ip.to_i + 1, end_ip.family).to_s

      low_range  = Nexpose::IPRange.new(start_ip.to_s, low_split)
      high_range = Nexpose::IPRange.new(high_split, end_ip.to_s)

      return [low_range, high_range]
    end

    # Adds assets to this site by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def add_ip_range(from, to)
      @assets << IPRange.new(from, to)
    end

    # Remove assets to this site by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def remove_ip_range(from, to)
      @assets = assets.reject { |asset| asset == IPRange.new(from, to) }
    end

    # Adds an asset to this site, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def add_asset(asset)
      obj = HostOrIP.convert(asset)
      @assets << obj
    end

    # Remove an asset to this site, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def remove_asset(asset)
      begin
        # If the asset registers as a valid IP, remove as IP.
        IPAddr.new(asset)
        remove_ip(asset)
      rescue ArgumentError => e
        if e.message == 'invalid address'
          remove_host(asset)
        else
          raise "Unable to parse asset: '#{asset}'. #{e.message}"
        end
      end
    end

    # Adds an asset to this site's exclude list, resolving whether an IP or 
    # hostname is provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def exclude_asset(asset)
      @exclude << HostOrIP.convert(asset)
    end

    alias_method :exclude_host, :exclude_asset
    alias_method :exclude_ip, :exclude_asset

    # Remove an asset from this site's exclude list, resolving whether an IP 
    # or hostname is provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def remove_excluded_asset(asset)
      @exclude.reject! { |existing_asset| existing_asset == HostOrIP.convert(asset) }
    end

    alias_method :remove_excluded_host, :remove_excluded_asset
    alias_method :remove_excluded_ip, :remove_excluded_asset

    # Adds assets to this site's exclude list by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def exclude_ip_range(from, to)
      @exclude << IPRange.new(from, to)
    end

    # Remove assets from this site's exclude list by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def remove_excluded_ip_range(from, to)
      @exclude.reject! { |asset| asset == IPRange.new(from, to) }
    end

    # Load an existing configuration from a Nexpose instance.
    #
    # @param [Connection] connection Connection to console where site exists.
    # @param [Fixnum] id Site ID of an existing site.
    # @return [Site] Site configuration loaded from a Nexpose console.
    #
    def self.load(connection, id, is_extended = false)
      if is_extended
        r = APIRequest.execute(connection.url,
                               %(<SiteConfigRequest session-id="#{connection.session_id}" site-id="#{id}" is_extended="true"/>))
      else
        r = APIRequest.execute(connection.url,
                               %(<SiteConfigRequest session-id="#{connection.session_id}" site-id="#{id}"/>))
      end
      site = parse(r.res)
      site.load_dynamic_attributes(connection) if site.dynamic?
      site
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
    # If the site is dynamic, connection and asset filter changes must be
    # saved through the DiscoveryConnection#update_site call.
    #
    # @param [Connection] connection Connection to console where this site will be saved.
    # @return [Fixnum] Site ID assigned to this configuration, if successful.
    #
    def save(connection)
      if dynamic?
        raise APIError.new(nil, 'Cannot save a dynamic site without a discovery connection configured.') unless @discovery_connection_id

        new_site = @id == -1
        save_dynamic_criteria(connection) if new_site

        # Have to retrieve and attach shared creds, or saving will fail.
        xml = _append_shared_creds_to_xml(connection, as_xml)
        response = AJAX.post(connection, '/data/site/config', xml)
        saved = REXML::XPath.first(REXML::Document.new(response), 'ajaxResponse')
        raise APIError.new(response, 'Failed to save dynamic site.') if saved.nil? || saved.attributes['success'].to_i != 1

        save_dynamic_criteria(connection) unless new_site
      else
        r = connection.execute('<SiteSaveRequest session-id="' + connection.session_id + '">' + to_xml + ' </SiteSaveRequest>')
        @id = r.attributes['site-id'].to_i if r.success
      end
      @id
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

      response = connection.execute(xml, '1.1', timeout: 60)
      Scan.parse(response.res) if response.success
    end

    # Save only the criteria of a dynamic site.
    #
    # @param [Connection] nsc Connection to a console.
    # @return [Fixnum] Site ID.
    #
    def save_dynamic_criteria(nsc)
      # Several parameters are passed through the URI
      params = { 'configID' => @discovery_connection_id,
                 'entityid' => @id > 0 ? @id : false,
                 'mode' => @id > 0 ? 'edit' : false }
      uri = AJAX.parameterize_uri('/data/site/saveSite', params)

      # JSON body of POST request contains details.
      details = { 'dynamic' => true,
                  'name' => @name,
                  'tag' => @description.nil? ? '' : @description,
                  'riskFactor' => @risk_factor,
                  # 'vCenter' => @discovery_connection_id,
                  'searchCriteria' => @criteria.nil? ? { 'operator' => 'AND' } : @criteria.to_h }
      json = JSON.generate(details)

      response = AJAX.post(nsc, uri, json, AJAX::CONTENT_TYPE::JSON)
      json = JSON.parse(response)
      if json['response'] =~ /success/
        if @id < 1
          @id = json['entityID'].to_i
        end
      else
        raise APIError.new(response, json['message'])
      end
      @id
    end

    # Retrieve the currrent filter criteria used by a dynamic site.
    #
    # @param [Connection] nsc Connection to a console.
    # @return [Criteria] Current criteria for the site.
    #
    def load_dynamic_attributes(nsc)
      response = AJAX.get(nsc, "/data/site/loadDynamicSite?entityid=#{@id}")
      json = JSON.parse(response)
      @discovery_connection_id = json['discoveryConfigs']['id']
      @criteria = Criteria.parse(json['searchCriteria'])
    end

    include Sanitize

    # Generate an XML representation of this site configuration
    #
    # @return [String] XML valid for submission as part of other requests.
    #
    def as_xml
      xml = REXML::Element.new('Site')
      xml.attributes['id'] = @id
      xml.attributes['name'] = @name
      xml.attributes['description'] = @description
      xml.attributes['riskfactor'] = @risk_factor
      xml.attributes['isDynamic'] = '1' if dynamic?
      # TODO This should be set to 'Amazon Web Services' for AWS.
      xml.attributes['dynamicConfigType'] = 'vSphere' if dynamic?

      if @description && !@description.empty?
        elem = REXML::Element.new('Description')
        elem.add_text(@description)
        xml.add_element(elem)
      end

      unless @users.empty?
        elem = REXML::Element.new('Users')
        @users.each { |user| elem.add_element('user', { 'id' => user }) }
        xml.add_element(elem)
      end

      xml.add_element(@organization.as_xml) if @organization

      elem = REXML::Element.new('Hosts')
      @assets.each { |a| elem.add_element(a.as_xml) }
      xml.add_element(elem)

      elem = REXML::Element.new('ExcludedHosts')
      @exclude.each { |e| elem.add_element(e.as_xml) }
      xml.add_element(elem)

      unless credentials.empty?
        elem = REXML::Element.new('Credentials')
        @credentials.each { |c| elem.add_element(c.as_xml) }
        xml.add_element(elem)
      end

      unless alerts.empty?
        elem = REXML::Element.new('Alerting')
        alerts.each { |a| elem.add_element(a.as_xml) }
        xml.add_element(elem)
      end

      elem = REXML::Element.new('ScanConfig')
      elem.add_attributes({ 'configID' => @id,
                            'name' => @scan_template_name || @scan_template,
                            'templateID' => @scan_template,
                            'configVersion' => @config_version || 3,
                            'engineID' => @engine })
      sched = REXML::Element.new('Schedules')
      @schedules.each { |s| sched.add_element(s.as_xml) }
      elem.add_element(sched)
      xml.add_element(elem)

      unless tags.empty?
        tag_xml = xml.add_element(REXML::Element.new('Tags'))
        @tags.each { |tag| tag_xml.add_element(tag.as_xml) }
      end

      xml
    end

    def to_xml
      as_xml.to_s
    end

    # Parse a response from a Nexpose console into a valid Site object.
    #
    # @param [REXML::Document] rexml XML document to parse.
    # @return [Site] Site object represented by the XML.
    #  ## TODO What is returned on failure?
    #
    def self.parse(rexml)
      rexml.elements.each('//Site') do |s|
        site = Site.new(s.attributes['name'])
        site.id = s.attributes['id'].to_i
        site.description = s.attributes['description']
        site.risk_factor = s.attributes['riskfactor'] || 1.0
        site.is_dynamic = true if s.attributes['isDynamic'] == '1'

        s.elements.each('Description') do |desc|
          site.description = desc.text
        end

        s.elements.each('Users/user') do |user|
          site.users << user.attributes['id'].to_i
        end

        s.elements.each('Organization') do |org|
          site.organization = Organization.parse(org)
        end

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
          site.credentials << SiteCredential.parse(cred)
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

        s.elements.each('Tags/Tag') do |tag|
          site.tags << TagSummary.parse_xml(tag)
        end

        return site
      end
      nil
    end

    def _append_shared_creds_to_xml(connection, xml)
      xml_w_creds = AJAX.get(connection, "/data/site/config?siteid=#{@id}")
      cred_xml = REXML::XPath.first(REXML::Document.new(xml_w_creds), 'Site/Credentials')
      unless cred_xml.nil?
        creds = REXML::XPath.first(xml, 'Credentials')
        if creds.nil?
          xml.add_element(cred_xml)
        else
          cred_xml.elements.each do |cred|
            if cred.attributes['shared'].to_i == 1
              creds.add_element(cred)
            end
          end
        end
      end
      xml
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

    def as_xml
      xml = REXML::Element.new('host')
      xml.text = @host
      xml
    end
    alias_method :to_xml_elem, :as_xml

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

    # @overload initialize(ip)
    #   @param [#to_s] from the IP single IP address.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0')
    #
    # @overload initialize(start_ip, end_ip)
    #   @param [#to_s] from the IP to start the range with.
    #   @param [#to_s] to the IP to end the range with.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0', '192.168.1.255')
    #
    # @overload initialize(cidr_range)
    #   @param [#to_s] from the CIDR notation IP address range.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0/24')
    #   @note The range will not be stripped of reserved IP addresses (such as
    #     x.x.x.0 and x.x.x.255).
    #
    # @return [IPRange] an IP address range of one or more addresses.
    def initialize(from, to = nil)
      @from = from
      @to = to unless from == to

      return unless @to.nil?

      range = IPAddr.new(@from.to_s).to_range
      unless range.one?
        @from = range.first.to_s
        @to = range.last.to_s
      end
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
      return 1 unless other.respond_to? :from
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
      return false unless other.respond_to? :from
      @from == other.from && @to == other.to
    end

    def include?(single_ip)
      return false unless single_ip.respond_to? :from
      from = IPAddr.new(@from).to_i
      to = @to.nil? ? from : IPAddr.new(@to).to_i
      other = IPAddr.new(single_ip.from).to_i
      (from..to).include?(other)
    end

    def hash
      to_xml.hash
    end

    def as_xml
      xml = REXML::Element.new('range')
      xml.add_attributes({ 'from' => @from, 'to' => @to })
      xml
    end
    alias_method :to_xml_elem, :as_xml

    def to_xml
      as_xml.to_s
    end
  end
end
