module Nexpose

  module NexposeAPI

    # Perform an asset filter search that will located assets matching the
    # provided conditions.
    #
    # For example, the following call will return assets with Java installed:
    #   nsc.filter(Search::Field::SOFTWARE, Search::Operator::CONTAINS, 'java')
    #
    # The following will show assets with Malware and Metasploit exposure:
    #   nsc.filter(Search::Field::VULNERABILITY_EXPOSURES,
    #              Search::Operator::INCLUDE,
    #              [Search::Value::VulnerabilityExposure::METASPLOIT,
    #               Search::Value::VulnerabilityExposure::MALWARE])
    #
    # @param [String] field Constant from Search::Field
    # @param [String] operator Constant from Search::Operator
    # @param [String] value Search term or constant from Search::Value
    # @return [Array[Asset]] List of matching assets.
    #
    def filter(field, operator, value = '')
      criterion = Search._map_criterion(field, operator, value)
      results = DataTable._get_json_table(self,
                                          '/data/asset/filterAssets',
                                          Search._create_payload(criterion))
      results.map { |a| Asset.new(a) }
    end

    # Perform a search that will match all of the criteria in the provided map.
    #
    # For example, the following call will return assets with Java and .NET:
    #   criteria = [{:field => Search::Field::SOFTWARE,
    #                :operator => Search::Operator::CONTAINS,
    #                :value => 'java'},
    #               {:field => Search::Field::SOFTWARE,
    #                :operator => Search::Operator::CONTAINS,
    #                :value => '.net'}]
    #   nsc.search_all(criteria)
    #
    # @param [Hash] Map of search criteria.
    # @return [Array[Asset]] List of matching assets.
    #
    def search_all(criteria)
      data = []
      criteria.each do |criterion|
        data << Search._map_criterion(criterion[:field], criterion[:operator], criterion[:value])
      end
      results = DataTable._get_json_table(self,
                                          '/data/asset/filterAssets',
                                          Search._create_payload(data))
      results.map { |a| Asset.new(a) }
    end

    # Perform a search that will match any of the criteria in the provided map.
    #
    # For example, the following call will return assets with Java or .NET:
    #   criteria = [{:field => Search::Field::SOFTWARE,
    #                :operator => Search::Operator::CONTAINS,
    #                :value => 'java'},
    #               {:field => Search::Field::SOFTWARE,
    #                :operator => Search::Operator::CONTAINS,
    #                :value => '.net'}]
    #   nsc.search_any(criteria)
    #
    # @param [Hash] Map of search criteria.
    # @return [Array[Asset]] List of matching assets.
    #
    def search_any(criteria)
      data = []
      criteria.each do |criterion|
        data << Search._map_criterion(criterion[:field],
                                      criterion[:operator],
                                      criterion[:value])
      end
      results = DataTable._get_json_table(self,
                                          '/data/asset/filterAssets',
                                          Search._create_payload(data, 'OR'))
      results.map { |a| Asset.new(a) }
    end
  end

  # Module for performing Asset Filter searches.
  #
  module Search
    module_function

    # Search constants

    # Only these values are accepted for a field value.
    #
    module Field

      # Search for an Asset by name.
      # Valid Operators: IS, IS_NOT, STARTS_WITH, ENDS_WITH, CONTAINS, NOT_CONTAINS
      ASSET = 'ASSET'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::AccessComplexity): LOW, MEDIUM, HIGH
      CVSS_ACCESS_COMPLEXITY = 'CVSS_ACCESS_COMPLEXITY'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::AccessVector): LOCAL, ADJACENT, NETWORK
      CVSS_ACCESS_VECTOR = 'CVSS_ACCESS_VECTOR'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::AuthenticationRequired): NONE, SINGLE, MULTIPLE
      CVSS_AUTHENTICATION_REQUIRED = 'CVSS_AUTHENTICATION_REQUIRED'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::CVSSImpact): NONE, PARTIAL, COMPLETE
      CVSS_AVAILABILITY_IMPACT = 'CVSS_AVAILABILITY_IMPACT'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::CVSSImpact): NONE, PARTIAL, COMPLETE
      CVSS_CONFIDENTIALITY_IMPACT = 'CVSS_CONFIDENTIALITY_IMPACT'

      # Valid Operators: IS, IS_NOT
      # Valid Values (See Value::CVSSImpact): NONE, PARTIAL, COMPLETE
      CVSS_INTEGRITY_IMPACT = 'CVSS_INTEGRITY_IMPACT'

      # Valid Operators: IS, IS_NOT, IN_RANGE, GREATER_THAN, LESS_THAN
      # Valid Values: Floats from 0.0 to 10.0
      CVSS_SCORE = 'CVSS_SCORE'

      # Valid Operators: IN, NOT_IN
      # Valid Values (See Value::HostType): UNKNOWN, VIRTUAL, HYPERVISOR, BARE_METAL
      HOST_TYPE = 'HOST_TYPE'

      # Valid Operators: IN, NOT_IN
      # Valid Values (See Value::IPType): IPv4, IPv6
      IP_ADDRESS_TYPE = 'IP_ADDRESS_TYPE'

      # Valid Operators: IN
      # Valid Values (See Value::IPType): IPv4, IPv6
      IP_ALT_ADDRESS_TYPE = 'IP_ALT_ADDRESS_TYPE'

      # Valid Operators: IN, NOT_IN
      IP_RANGE = 'IP_RANGE'

      # Valid Operators: CONTAINS, NOT_CONTAINS, IS_EMPTY, IS_NOT_EMPTY
      OS = 'OS'

      # Valid Operators: IS
      # Valid Values (See Value::PCICompliance): PASS, FAIL
      PCI_COMPLIANCE_STATUS = 'PCI_COMPLIANCE_STATUS'

      # Valid Operators: IS, IS_NOT, IN_RANGE, GREATER_THAN, LESS_THAN
      RISK_SCORE = 'RISK_SCORE'

      # Search based on the last scan date of an asset.
      # Valid Operators: ON_OR_BEFORE, ON_OR_AFTER, BETWEEN, EARLIER_THAN,
      #                  WITHIN_THE_LAST
      # Valid Values: Use Value::ScanDate::FORMAT for date arguments.
      #               Use FixNum for day arguments.
      SCAN_DATE = 'SCAN_DATE'

      # Valid Operators: CONTAINS, NOT_CONTAINS
      SERVICE = 'SERVICE'

      # Search based on the Site ID of an asset.
      # (Note that underlying search used Site ID, despite 'site name' value.)
      # Valid Operators: IN, NOT_IN
      # Valid Values: FixNum Site ID of the site.
      SITE_ID = 'SITE_NAME'

      # Valid Operators: CONTAINS, NOT_CONTAINS
      SOFTWARE = 'SOFTWARE'

      # Search against vulnerability titles that an asset contains.
      # Valid Operators: CONTAINS, NOT_CONTAINS
      VULNERABILITY = 'VULNERABILITY'

      # Valid Operators: INCLUDE, DO_NOT_INCLUDE
      # Valid Values (See Value::VulnerabilityExposure): MALWARE, METASPLOIT, DATABASE
      VULNERABILITY_EXPOSURES = 'VULNERABILITY_EXPOSURES'
    end

    # List of acceptable operators. Not all fields accept all operators.
    #
    module Operator
      CONTAINS = 'CONTAINS'
      NOT_CONTAINS = 'NOT_CONTAINS'
      IS = 'IS'
      IS_NOT = 'IS_NOT'
      IN = 'IN'
      NOT_IN = 'NOT_IN'
      IN_RANGE = 'IN_RANGE'
      STARTS_WITH = 'STARTS_WITH'
      ENDS_WITH = 'ENDS_WITH'
      ON_OR_BEFORE = 'ON_OR_BEFORE'
      ON_OR_AFTER = 'ON_OR_AFTER'
      WITHIN_THE_LAST = 'WITHIN_THE_LAST'
      GREATER_THAN = 'GREATER_THAN'
      LESS_THAN = 'LESS_THAN'
      IS_EMPTY = 'IS_EMPTY'
      IS_NOT_EMPTY = 'IS_NOT_EMPTY'
      INCLUDE = 'INCLUDE'
      DO_NOT_INCLUDE = 'DO_NOT_INCLUDE'
    end

    # Specialized values used by certain search fields
    #
    module Value

      module AccessComplexity
        LOW = 'L'
        MEDIUM = 'M'
        HIGH = 'H'
      end

      module AccessVector
        LOCAL = 'L'
        ADJACENT = 'A'
        NETWORK = 'N'
      end

      module AuthenticationRequired
        NONE = 'N'
        SINGLE = 'S'
        MULTIPLE = 'M'
      end

      module CVSSImpact
        NONE = 'N'
        PARTIAL = 'P'
        COMPLETE = 'C'
      end

      module HostType
        UNKNOWN = '0'
        VIRTUAL = '1'
        HYPERVISOR = '2'
        BARE_METAL = '3'
      end

      module IPType
        IPv4 = '0'
        IPv6 = '1'
      end

      module PCICompliance
        PASS = '1'
        FAIL = '0'
      end

      module ScanDate
        # Pass this format to #strftime() to get expected format for requests.
        FORMAT = '%m/%d/%Y'
      end

      module VulnerabilityExposure
        MALWARE = 'type:"malware_type", name:"malwarekit"'
        # TODO: A problem in Nexpose causes these values to not be constant.
        METASPLOIT = 'type:"exploit_source_type", name:"2"'
        DATABASE = 'type:"exploit_source_type", name:"1"'
      end
    end

    # Turn criterion into the format required by the Asset Filter calls.
    #
    def _map_criterion(field, operator, value)
      { 'metadata' => { 'fieldName' => field },
        'operator' => operator,
        'values' => value.kind_of?(Array) ? value : [value] }
    end

    # Generate the payload needed for a POST request for Asset Filter.
    #
    def _create_payload(criteria, match = 'AND')
      match = match =~ /(?:and|all)/i ? 'AND' : 'OR'
      criteria = [criteria] unless criteria.kind_of?(Array)
      json = JSON.generate({ 'operator' => match,
                             'criteria' => criteria })
      { 'dir' => -1,
        'results' => -1,
        'sort' => 'assetIP',
        'startIndex' => -1,
        'table-id' => 'assetfilter',
        'searchCriteria' => json }
    end
  end

  # Asset data as returned by an Asset Filter search.
  #
  class Asset

    # Unique identifier of this asset. Also known as device ID.
    attr_reader :id

    attr_reader :ip
    attr_reader :name
    attr_reader :os

    attr_reader :exploit_count
    attr_reader :malware_count
    attr_reader :vuln_count
    attr_reader :risk_score

    attr_reader :site_id
    attr_reader :last_scan

    def initialize(json)
      @id = json['assetID']['ID'].to_i
      @ip = json['assetIP']
      @name = json['assetName']
      @os = json['assetOSName']
      @exploit_count = json['exploitCount'].to_i
      @malware_count = json['malwareCount'].to_i
      @vuln_count = json['vulnCount'].to_i
      @risk_score = json['riskScore'].to_f
      @site_id = json['siteID']
      @last_scan = Time.at(json['lastScanDate'] / 1000)
    end
  end
end
