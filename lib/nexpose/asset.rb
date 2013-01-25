module Nexpose
  module NexposeAPI

    # Perform a search that will match the provided conditions.
    #
    # For example, the following call will return assets with Java installed:
    #   nsc.search(Search::Field::SOFTWARE, Search::Operator::CONTAINS, 'java')
    #
    # The following will show assets with Malware and Metasploit exposure:
    #   nsc.search(Search::Field::VULNERABILITY_EXPOSURES,
    #              Search::Operator::INCLUDE,
    #              [Search::Value::VulnerabilityExposure::METASPLOIT,
    #               Search::Value::VulnerabilityExposure::MALWARE])
    def search(field, operator, value = '')
      criterion = Search::map_criterion(field, operator, value)
      Search::post_search_request(@host, @port, @session_id, Search::generate_post_data(criterion))
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
    def search_all(criteria)
      data = []
      criteria.each do |criterion|
        data << Search::map_criterion(criterion[:field], criterion[:operator], criterion[:value])
      end
      Search::post_search_request(@host, @port, @session_id, Search::generate_post_data(data))
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
    def search_any(criteria)
      data = []
      criteria.each do |criterion|
        data << Search::map_criterion(criterion[:field], criterion[:operator], criterion[:value])
      end
      Search::post_search_request(@host, @port, @session_id, Search::generate_post_data(data, 'OR'))
    end
  end

  module Search

    # Search constants

    # Only these values are accepted for a field value.
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
      # Valid Operators: ON_OR_BEFORE, ON_OR_AFTER, BETWEEN, EARLIER_THAN, WITHIN_THE_LAST
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
        METASPLOIT = 'type:"exploit_source_type", name:"2"'
        DATABASE = 'type:"exploit_source_type", name:"1"'
      end
    end

    private

    # Format search criterion into expected format for asset filter search.
    def self.map_criterion(field, operator, value)
      {'metadata' => {'fieldName' => field},
       'operator' => operator,
       'values' => value.kind_of?(Array) ? value : [value]}
    end

    # Generate POST data packet for asset filter search.
    def self.generate_post_data(criteria, match = 'AND')
      criteria = [criteria] unless criteria.kind_of?(Array)
      json = JSON.generate({'operator' => match,
                            'criteria' => criteria})
      {'dir' => -1,
       'results' => -1,
       'sort' => -1,
       'startIndex' => -1,
       'searchCriteria' => json}
    end

    # POST a search request to the Nexpose console.
    # Returns an Array of Assets.
    def self.post_search_request(host, port, session_id, data)
      url = "https://#{host}:#{port}/data/asset/filterAssets"
      header = {:content_type => 'application/x-www-form-urlencode',
                :nexposeCCSessionID => session_id,
                :cookies => {:nexposeCCSessionID => session_id}}
      result = RestClient.post(url, data, header)
      if result.empty?
        []
      elsif result =~ /An error has prevented this table from being populated/
        raise 'Unable to retrieve results.'
      else
        result = JSON.parse(result, :symbolize_names => true)
        result[:records].map { |record| Asset.parse(record) }
      end
    end
  end

  # Asset as returned from a asset filter search.
  #
  class Asset
    attr_accessor :id, :ip, :name, :os,
      :last_scan_date, # :scan_id,
      :site_id, :site_name,
      :risk_score, :exploit_count, :malware_count, :vuln_count
      # Dead stores? Returned by Nexpose, but always empty/nil.
      # :asset_cpe_name, :os_id, :node_ids, :nodes, :node_count, :port, :product_name

    def initialize
      yield(self) if block_given?
    end

    # Parse the JSON results from an asset filter search into an Asset.
    #
    def self.parse(json)
      Asset.new do |asset|
        asset.id = json[:assetID][:ID]
        asset.ip = json[:assetIP]
        asset.name = json[:assetName]
        asset.os = json[:assetOSName]

        asset.last_scan_date = Time.at(json[:lastScanDate] / 1000.0)
        # asset.scan_id = json[:scanID]

        asset.site_id = json[:siteID]
        asset.site_name = json[:siteName]

        asset.risk_score = json[:riskScore]
        asset.exploit_count = json[:exploitCount]
        asset.malware_count = json[:malwareCount]
        asset.vuln_count = json[:vulnCount]

        # asset.asset_cpe_name = json[:assetCPEName]
        # asset.os_id = json[:assetOSID]
        # asset.node_ids = json[:nodeIDs]
        # asset.nodes = json[:nodes]
        # asset.node_count = json[:numNodes]
        # asset.port = json[:port]
        # asset.product_name = json[:productName]
      end
    end
  end
end
