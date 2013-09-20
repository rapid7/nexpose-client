module Nexpose
  module NexposeAPI

    # List the scan templates currently configured on the console.
    #
    # @return [Array[String]] list of scan templates IDs.
    #
    def list_scan_templates
      templates = JSON.parse(AJAX.get(self, '/data/scan/templates'))
      templates['valueList']
    end

    alias_method :scan_templates, :list_scan_templates

    # Delete a scan template from the console.
    # Cannot be used to delete a built-in template.
    #
    # @param [String] id Unique identifier of an existing scan template.
    #
    def delete_scan_template(id)
      AJAX.delete(self, "/data/scan/templates/#{URI.encode(id)}")
    end
  end

  # Configuration object for a scan template.
  # This class is only a partial representation of some of the features
  # available for configuration.
  #
  class ScanTemplate

    # Unique identifier of the scan template.
    attr_accessor :id

    attr_accessor :name
    attr_accessor :description

    # Whether to correlate reliable checks with regular checks.
    attr_accessor :correlate

    # Parsed XML of a scan template
    attr_accessor :xml

    def initialize(xml)
      @xml = xml

      root = REXML::XPath.first(xml, 'ScanTemplate')
      @id = root.attributes['id']
      @id = nil if @id == '#NewScanTemplate#'

      desc = REXML::XPath.first(root, 'templateDescription')
      if desc
        @name = desc.attributes['title']
        @description = desc.text.to_s
      end

      vuln_checks = REXML::XPath.first(root, 'VulnerabilityChecks')
      @correlate = vuln_checks.attributes['correlate'] == '1'
    end

    # Get a list of the check categories enabled for this scan template.
    #
    # @return [Array[String]] List of enabled categories.
    #
    def checks_by_category
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks/Enabled')
      checks.elements.to_a('VulnCategory').map { |c| c.attributes['name'] }
    end

    # Enable checks by category for this template.
    #
    # @param [String] category Category to enable. @see #list_vuln_categories
    #
    def enable_checks_by_category(category)
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks')
      checks.elements.delete("Disabled/VulnCategory[@name='#{category}']")
      checks.elements['Enabled'].add_element('VulnCategory', { 'name' => category })
    end

    # Disable checks by category for this template.
    #
    # @param [String] category Category to disable. @see #list_vuln_categories
    #
    def disable_checks_by_category(category)
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks')
      checks.elements.delete("Enabled/VulnCategory[@name='#{category}']")
      checks.elements['Disabled'].add_element('VulnCategory', { 'name' => category })
    end

    # Remove checks by category for this template.
    #
    # @param [String] category Category to remove. @see #list_vuln_categories
    #
    def remove_checks_by_category(category)
      checks = REXML::XPath.first(@xml, '//VulnerabilityChecks')
      checks.elements.delete("Disabled/VulnCategory[@name='#{category}']")
      checks.elements.delete("Enabled/VulnCategory[@name='#{category}']")
    end

    # Save this scan template configuration to a Nexpose console.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    #
    def save(nsc)
      root = REXML::XPath.first(@xml, 'ScanTemplate')
      existing = root.attributes['id'] == @id
      root.attributes['id'] = @id unless existing

      desc = REXML::XPath.first(root, 'templateDescription')
      desc.attributes['title'] = @name
      desc.text = @description

      vuln_checks = REXML::XPath.first(root, 'VulnerabilityChecks')
      vuln_checks.attributes['correlate'] = (@correlate ? '1' : '0')

      if existing
        response = AJAX.put(nsc, "/data/scan/templates/#{URI.encode(id)}", xml)
      else
        response = JSON.parse(AJAX.post(nsc, '/data/scan/templates', xml))
        @id = response['value']
      end
    end

    # Load an existing scan template.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] id Unique identifier of an existing scan template.
    #   If no ID is provided, a blank, base template will be returned.
    # @return [ScanTemplate] The requested scan template configuration.
    #
    def self.load(nsc, id = nil)
      if id
        response = JSON.parse(AJAX.get(nsc, "/data/scan/templates/#{URI.encode(id)}"))
        xml = response['value']
      else
        xml = AJAX.get(nsc, '/ajax/scantemplate_config.txml')
      end
      new(REXML::Document.new(xml))
    end

    # Copy an existing scan template, changing the id and title.
    #
    # @param [Connection] nsc API connection to a Nexpose console.
    # @param [String] id Unique identifier of an existing scan template.
    # @return [ScanTemplate] A copy of the requested scan template configuration.
    #
    def self.copy(nsc, id)
      dupe = load(nsc, id)
      dupe.id = "#{dupe.id}-copy"
      dupe.title = "#{dupe.title} Copy"
      dupe
    end
  end
end
