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
  class Site < APIObject
    include JsonSerializer
    # The site ID. An ID of -1 is used to designate a site that has not been
    # saved to a Nexpose console.
    attr_accessor :id

    # Unique name of the site. Required.
    attr_accessor :name

    # Description of the site.
    attr_accessor :description

    # Included scan targets. May be IPv4, IPv6, DNS names, IPRanges or assetgroup ids.
    attr_accessor :included_scan_targets

    # Excluded scan targets. May be IPv4, IPv6, DNS names, IPRanges or assetgroup ids.
    attr_accessor :excluded_scan_targets

    # Scan template to use when starting a scan job. Default: full-audit-without-web-spider
    attr_accessor :scan_template_id

    # Friendly name of scan template to use when starting a scan job.
    # Value is populated when a site is saved or loaded from a console.
    attr_accessor :scan_template_name

    # Scan Engine to use. Will use the default engine if nil or -1.
    attr_accessor :engine_id

    # [Array] Schedule starting dates and times for scans, and set their frequency.
    attr_accessor :schedules

    # The risk factor associated with this site. Default: 1.0
    attr_accessor :risk_factor

    # [Array] Collection of credentials associated with this site. Does not
    # include shared credentials.
    attr_accessor :site_credentials

    # [Array] Collection of shared credentials associated with this site.
    attr_accessor :shared_credentials

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
    attr_accessor :dynamic

    # Asset filter criteria if this site is dynamic.
    attr_accessor :search_criteria

    # discovery config of the discovery connection associated with this site if it is dynamic.
    attr_accessor :discovery_config

    # [Array[TagSummary]] Collection of TagSummary
    attr_accessor :tags

    # Site constructor. Both arguments are optional.
    #
    # @param [String] name Unique name of the site.
    # @param [String] scan_template_id ID of the scan template to use.
    def initialize(name = nil, scan_template_id = 'full-audit-without-web-spider')
      @name = name
      @scan_template_id = scan_template_id
      @id = -1
      @risk_factor = 1.0
      @config_version = 3
      @is_dynamic = false
      @schedules = []
      @included_scan_targets = { addresses: [], asset_groups: [] }
      @excluded_scan_targets = { addresses: [], asset_groups: [] }
      @site_credentials = []
      @shared_credentials = []
      @alerts = []
      @users = []
      @tags = []
    end

    # Returns true when the site is dynamic.
    def isdynamic?
      dynamic
    end

    # Adds an asset to this site by host name.
    #
    # @param [String|HostName] hostname FQDN or DNS-resolvable host name of an asset.
    def include_host(hostname)
      hostname = HostName.new(hostname) if hostname.is_a? String
      raise 'Invalid hostname specified' unless hostname.is_a? HostName
      @included_scan_targets[:addresses] << hostname
    end

    # Remove an asset to this site by host name.
    #
    # @param [String|HostName] hostname FQDN or DNS-resolvable host name of an asset.
    def remove_included_host(hostname)
      hostname = HostName.new(hostname) if hostname.is_a? String
      raise 'Invalid hostname specified' unless hostname.is_a? HostName
      @included_scan_targets[:addresses].reject! { |t| t.eql? hostname }
    end

    # Adds an asset to this site by IP address.
    #
    # @param [String|IPRange] ip IP address of an asset.
    def include_ip(ip)
      begin
        if ip.is_a? String
          IPAddr.new(ip)
          ip = IPRange.new(ip)
        end
        raise 'Invalid IP address specified' unless ip.is_a? IPRange
        @included_scan_targets[:addresses] << ip
      rescue ArgumentError => e
        raise e.message
      end
    end

    # Remove an asset to this site by IP address.
    #
    # @param [String|IPRange] ip IP address of an asset.
    def remove_included_ip(ip)
      begin
        if ip.is_a? String
          IPAddr.new(ip)
          ip = IPRange.new(ip)
        end
        raise 'Invalid IP address specified' unless ip.is_a? IPRange
        @included_scan_targets[:addresses].reject! { |t| t.eql? ip }
      rescue ArgumentError => e
        raise e.message
      end
    end

    # Adds assets to this site by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def include_ip_range(from, to)
      begin
        from_ip = IPAddr.new(from)
        to_ip = IPAddr.new(to)
        (from_ip..to_ip)
        if (from_ip..to_ip).to_a.size == 0
          raise 'Invalid IP range specified'
        end
        @included_scan_targets[:addresses] << IPRange.new(from, to)
      rescue ArgumentError => e
        raise "#{e.message} in given IP range"
      end
    end

    # Remove assets to this site by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def remove_included_ip_range(from, to)
      begin
        from_ip = IPAddr.new(from)
        to_ip = IPAddr.new(to)
        (from_ip..to_ip)
        if (from_ip..to_ip).to_a.size == 0
          raise 'Invalid IP range specified'
        end
        @included_scan_targets[:addresses].reject! { |t| t.eql? IPRange.new(from, to) }
      rescue ArgumentError => e
        raise "#{e.message} in given IP range"
      end
    end

    # Adds an asset to this site included scan targets, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def include_asset(asset)
      @included_scan_targets[:addresses] << HostOrIP.convert(asset)
    end

    # Remove an asset to this site included scan targets, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def remove_included_asset(asset)
      @included_scan_targets[:addresses].reject! { |existing_asset| existing_asset == HostOrIP.convert(asset) }
    end

    # Adds an asset to this site excluded scan targets by host name.
    #
    # @param [String|HostName] hostname FQDN or DNS-resolvable host name of an asset.
    def exclude_host(hostname)
      hostname = HostName.new(hostname) if hostname.is_a? String
      raise 'Invalid hostname specified' unless hostname.is_a? HostName
      @excluded_scan_targets[:addresses] << hostname
    end

    # Remove an asset from this site excluded scan targets by host name.
    #
    # @param [String|HostName] hostname FQDN or DNS-resolvable host name of an asset.
    def remove_excluded_host(hostname)
      hostname = HostName.new(hostname) if hostname.is_a? String
      raise 'Invalid hostname specified' unless hostname.is_a? HostName
      @excluded_scan_targets[:addresses].reject! { |t| t.eql? hostname }
    end

    # Adds an asset to this site excluded scan targets by IP address.
    #
    # @param [String|IPRange] ip IP address of an asset.
    def exclude_ip(ip)
      begin
        if ip.is_a? String
          IPAddr.new(ip)
          ip = IPRange.new(ip)
        end
        raise 'Invalid IP address specified' unless ip.is_a? IPRange
        @included_scan_targets[:addresses] << ip
      rescue ArgumentError => e
        raise e.message
      end
    end

    # Remove an asset from this site excluded scan targets by IP address.
    #
    # @param [String|IPRange] ip IP address of an asset.
    def remove_excluded_ip(ip)
      begin
        if ip.is_a? String
          IPAddr.new(ip)
          ip = IPRange.new(ip)
        end
        raise 'Invalid IP address specified' unless ip.is_a? IPRange
        @included_scan_targets[:addresses].reject! { |t| t.eql? ip }
      rescue ArgumentError => e
        raise e.message
      end
    end

    # Adds assets to this site excluded scan targets by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def exclude_ip_range(from, to)
      begin
        from_ip = IPAddr.new(from)
        to_ip = IPAddr.new(to)
        (from_ip..to_ip)
        if (from_ip..to_ip).to_a.size == 0
          raise 'Invalid IP range specified'
        end
        @included_scan_targets[:addresses] << IPRange.new(from, to)
      rescue ArgumentError => e
        raise "#{e.message} in given IP range"
      end
    end

    # Remove assets from this site excluded scan targets by IP address range.
    #
    # @param [String] from Beginning IP address of a range.
    # @param [String] to Ending IP address of a range.
    def remove_excluded_ip_range(from, to)
      begin
        from_ip = IPAddr.new(from)
        to_ip = IPAddr.new(to)
        (from_ip..to_ip)
        if (from_ip..to_ip).to_a.size == 0
          raise 'Invalid IP range specified'
        end
        @included_scan_targets[:addresses].reject! { |t| t.eql? IPRange.new(from, to) }
      rescue ArgumentError => e
        raise "#{e.message} in given IP range"
      end
    end

    # Adds an asset to this site excluded scan targets, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def exclude_asset(asset)
      @excluded_scan_targets[:addresses] << HostOrIP.convert(asset)
    end

    # Removes an asset to this site excluded scan targets, resolving whether an IP or hostname is
    # provided.
    #
    # @param [String] asset Identifier of an asset, either IP or host name.
    #
    def remove_excluded_asset(asset)
      @excluded_scan_targets[:addresses].reject! { |existing_asset| existing_asset == HostOrIP.convert(asset) }
    end

    # Adds an asset group ID to this site included scan targets.
    #
    # @param [Integer] asset_group_id Identifier of an assetGroupID.
    #
    def include_asset_group(asset_group_id)
      validate_asset_group(asset_group_id)
      @included_scan_targets[:asset_groups] << asset_group_id.to_i
    end

    # Adds an asset group ID to this site included scan targets.
    #
    # @param [Integer] asset_group_id Identifier of an assetGroupID.
    #
    def remove_included_asset_group(asset_group_id)
      validate_asset_group(asset_group_id)
      @included_scan_targets[:asset_groups].reject! { |t| t.eql? asset_group_id.to_i }
    end

    # Adds an asset group ID to this site excluded scan targets.
    #
    # @param [Integer] asset_group_id Identifier of an assetGroupID.
    #
    def exclude_asset_group(asset_group_id)
      validate_asset_group(asset_group_id)
      @excluded_scan_targets[:asset_groups] << asset_group_id.to_i
    end

    # Adds an asset group ID to this site excluded scan targets.
    #
    # @param [Integer] asset_group_id Identifier of an assetGroupID.
    #
    def remove_excluded_asset_group(asset_group_id)
      validate_asset_group(asset_group_id)
      @excluded_scan_targets[:asset_groups].reject! { |t| t.eql? asset_group_id.to_i }
    end

    def validate_asset_group(asset_group_id)
      begin
        Integer(asset_group_id)
      rescue ArgumentError => e
        raise "Invalid asset_group id. #{e.message}"
      end

      raise 'Invalid asset_group id. Must be positive number.' if asset_group_id.to_i < 1
    end

    def self.from_hash(hash)
      site = new(hash[:name], hash[:scan_template_id])
      hash.each do |k, v|
        site.instance_variable_set("@#{k}", v)
      end

      # Convert each string address to either a HostName or IPRange object
      included_scan_targets = { addresses: [], asset_groups: [] }
      site.included_scan_targets[:addresses].each { |asset| included_scan_targets[:addresses] << HostOrIP.convert(asset) }
      included_scan_targets[:asset_groups] = site.included_scan_targets[:asset_groups]
      site.included_scan_targets = included_scan_targets

      excluded_scan_targets = { addresses: [], asset_groups: [] }
      site.excluded_scan_targets[:addresses].each { |asset| excluded_scan_targets[:addresses] << HostOrIP.convert(asset) }
      excluded_scan_targets[:asset_groups] = site.excluded_scan_targets[:asset_groups]
      site.excluded_scan_targets = excluded_scan_targets

      site
    end

    def to_json
      JSON.generate(to_h)
    end

    def to_h
      included_scan_targets = { addresses: [], asset_groups: [] }
      excluded_scan_targets = { addresses: [], asset_groups: [] }
      @included_scan_targets[:addresses].each { |a| included_scan_targets[:addresses] << a.to_s unless a.nil? }
      @included_scan_targets[:asset_groups].each { |a| included_scan_targets[:asset_groups] << a.to_i unless a.nil? }
      @excluded_scan_targets[:addresses].each { |a| excluded_scan_targets[:addresses] << a.to_s unless a.nil? }
      @excluded_scan_targets[:asset_groups].each { |a| excluded_scan_targets[:asset_groups] << a.to_i unless a.nil? }


      {
          id: id,
          name: name,
          description: description,
          included_scan_targets: included_scan_targets,
          excluded_scan_targets: excluded_scan_targets,
          engine_id: engine_id,
          scan_template_id: scan_template_id,
          risk_factor: risk_factor,
          schedules: schedules,
          shared_credentials: @shared_credentials.map {|cred| cred.to_h},
          site_credentials: @site_credentials.map {|cred| cred.to_h},
          discovery_config: @discovery_config.to_h,
          search_criteria: @search_criteria.to_h,
          tags: @tags.map{|tag| tag.to_h}
      }
    end

    require 'json'
    # Load an site from the provided console.
    #
    # @param [Connection] nsc Active connection to a Nexpose console.
    # @param [String] id Unique identifier of a site.
    # @return [Site] The requested site, if found.
    #
    def self.load(nsc, id)
      uri = "/api/2.1/site_configurations/#{id}"
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true)
      site = new.deserialize(hash)

      site.site_credentials = site.site_credentials.map {|cred| Nexpose::SiteCredentials.new.object_from_hash(nsc,cred)}
      site.shared_credentials = site.shared_credentials.map {|cred| Nexpose::SiteCredentials.new.object_from_hash(nsc,cred)}
      unless site.discovery_config.nil?
        site.discovery_config = Nexpose::DiscoveryConnection.new.object_from_hash(nsc,site.discovery_config)
      end
      unless site.search_criteria.nil?
        site.search_criteria = Nexpose::DiscoveryConnection::Criteria.parseHash(site.search_criteria)
      end
      site.tags = Tag.load_tags(hash[:tags])
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
        new_site = @id == -1

        if new_site
          resp = AJAX.post(connection, '/api/2.1/site_configurations/', to_json, AJAX::CONTENT_TYPE::JSON)
          @id = resp.to_i
        else
          resp = AJAX.put(connection, "/api/2.1/site_configurations/#{@id}", to_json, AJAX::CONTENT_TYPE::JSON)
        end

        # Retrieve the scan engine and shared credentials and add them to the site configuration
        site_config = Site.load(connection, @id)
        @engine_id = site_config.engine_id
        @shared_credentials = site_config.shared_credentials

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

    def to_s
      @host.to_s
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

    def as_xml
      xml = REXML::Element.new('range')
      xml.add_attributes({ 'from' => @from, 'to' => @to })
      xml
    end
    alias_method :to_xml_elem, :as_xml

    def to_xml
      as_xml.to_s
    end

    def to_s
      return from.to_s if to.nil?
      "#{from.to_s} - #{to.to_s}"
    end
  end
end
