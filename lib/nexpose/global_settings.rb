module Nexpose
  # Object used to manage the global settings of a Nexpose console.
  #
  class GlobalSettings
    # IP addresses and/or host names that will be excluded from scanning across
    # all sites.
    attr_accessor :asset_exclusions

    # XML document representing the entire configuration.
    attr_reader :xml

    # Private constructor. See #load method for retrieving a settings object.
    #
    def initialize(xml)
      @xml = xml

      @asset_exclusions = _parse_exclusions(xml)
    end

    # Save any updates to this settings object to the Nexpose console.
    #
    # @param [Connection] nsc Connection to a Nexpose console.
    # @return [Boolean] Whether saving was successful.
    #
    def save(nsc)
      # load method can return XML missing this required attribute.
      unless REXML::XPath.first(xml, '//*[@recalculation_duration]')
        risk_model = REXML::XPath.first(xml, '//riskModel')
        risk_model.add_attribute('recalculation_duration', 'do_not_recalculate')
      end

      _replace_exclusions(xml, asset_exclusions)

      response = AJAX.post(nsc, '/data/admin/global-settings', xml)
      XMLUtils.success? response
    end

    # Load the global settings from a Nexpose console.
    #
    # @param [Connection] nsc Connection to a Nexpose console.
    # @return [GlobalSettings] Settings object for the console.
    #
    def self.load(nsc)
      response = AJAX.get(nsc, '/data/admin/global-settings')
      new(REXML::Document.new(response))
    end

    # Add an asset exclusion setting.
    #
    # @param [IPRange|HostName|String] host_or_ip Host or IP (range) to exclude
    #   from scanning by the Nexpose console.
    #
    def add_exclusion(host_or_ip)
      asset = host_or_ip
      unless host_or_ip.respond_to?(:host) || host_or_ip.respond_to?(:from)
        asset = HostOrIP.convert(host_or_ip)
      end
      @asset_exclusions << asset
    end

    # Remove an asset exclusion setting.
    # If you need to remove a range of IPs, be sure to explicitly supply an
    # IPRange object to the method.
    #
    # @param [IPRange|HostName|String] host_or_ip Host or IP (range) to remove
    #   from the exclusion list.
    #
    def remove_exclusion(host_or_ip)
      asset = host_or_ip
      unless host_or_ip.respond_to?(:host) || host_or_ip.respond_to?(:from)
        # Attept to convert String to appropriate object.
        asset = HostOrIP.convert(host_or_ip)
      end
      @asset_exclusions = asset_exclusions.reject { |a| a.eql? asset }
    end

    # Internal method for parsing exclusions from XML.
    def _parse_exclusions(xml)
      exclusions = []
      xml.elements.each('//range') do |elem|
        to = elem.attribute('to').nil? ? nil : elem.attribute('to').value
        exclusions << IPRange.new(elem.attribute('from').value, to)
      end
      xml.elements.each('//host') do |elem|
        exclusions << HostName.new(elem.text)
      end
      exclusions
    end

    # Internal method for updating exclusions before saving.
    def _replace_exclusions(xml, exclusions)
      xml.elements.delete('//ExcludedHosts')
      elem = xml.root.add_element('ExcludedHosts')
      exclusions.each do |exclusion|
        elem.add_element(exclusion.as_xml)
      end
    end
  end
end
