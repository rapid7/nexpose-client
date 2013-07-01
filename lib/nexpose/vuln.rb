module Nexpose
  module NexposeAPI
    include XMLUtils

    # Retrieve summary details of all vulnerabilities.
    #
    # @param [Boolean] full Whether or not to gather the full summary.
    #   Without the flag, only id, title, and severity are returned.
    #   It can take twice a long to retrieve full summary information.
    # @return [Array[Vulnerability|VulnerabilitySummary]] Collection of all known vulnerabilities.
    #
    def vuln_listing(full = false)
      xml = make_xml('VulnerabilityListingRequest')
      # TODO Add a flag to do stream parsing of the XML to improve performance.
      response = execute(xml, '1.2')
      vulns = []
      if response.success
        response.res.elements.each('VulnerabilityListingResponse/VulnerabilitySummary') do |vuln|
          if full
            vulns << VulnerabilitySummary::parse(vuln)
          else
            vulns << Vulnerability.new(vuln.attributes['id'],
                                       vuln.attributes['title'],
                                       vuln.attributes['severity'].to_i)
          end
        end
      end
      vulns
    end

    alias_method :vulns, :vuln_listing

    # Retrieve details for a vulnerability.
    #
    # @param [String] vuln_id Nexpose vulnerability ID, such as 'windows-duqu-cve-2011-3402'.
    # @return [VulnerabilityDetail] Details of the requested vulnerability.
    #
    def vuln_details(vuln_id)
      xml = make_xml('VulnerabilityDetailsRequest', {'vuln-id' => vuln_id})
      response = execute(xml, '1.2')
      if response.success
        response.res.elements.each('VulnerabilityDetailsResponse/Vulnerability') do |vuln|
          return VulnerabilityDetail::parse(vuln)
        end
      end
    end
  end

  # Basic vulnerability information. Only includes id, title, and severity.
  #
  class Vulnerability

    # The unique ID string for this vulnerability
    attr_reader :id

    # The title of this vulnerability
    attr_reader :title

    # How critical the vulnerability is on a scale of 1 to 10.
    attr_reader :severity

    def initialize(id, title, severity)
      @id, @title, @severity = id, title, severity
    end
  end

  # Summary of a vulnerability.
  #
  class VulnerabilitySummary < Vulnerability

    # PCI severity value for the vulnerability on a scale of 1 to 5. 
    attr_accessor :pci_severity

    # Whether all checks for the vulnerability are safe.
    # Unsafe checks may cause denial of service or otherwise disrupt system performance.
    attr_accessor :safe

    # A vulnerability is considered “credentialed” when all of its checks
    # require credentials or if the check depends on previous authentication
    # during a scan.
    attr_accessor :credentials

    # When this vulnerability was first included in the application.
    attr_accessor :added

    # The last date the vulnerability was modified.
    attr_accessor :modified

    # The date when the information about the vulnerability was first released.
    attr_accessor :published

    # How the vulnerability is exploited according to PCI standards.
    attr_accessor :cvss_vector

    # The computation of the Common Vulnerability Scoring System indicating
    # compliance with PCI standards on a scale from 0 to 10.0.
    attr_accessor :cvss_score

    def self.parse_attributes(xml)
      vuln = new(xml.attributes['id'],
                 xml.attributes['title'],
                 xml.attributes['severity'].to_i)

      vuln.pci_severity = xml.attributes['pciSeverity'].to_i
      vuln.safe = xml.attributes['safe'] == 'true'  # or xml.attributes['safe'] == '1'
      vuln.added = Date::parse(xml.attributes['added'])
      vuln.modified = Date::parse(xml.attributes['modified'])
      vuln.credentials = xml.attributes['requiresCredentials'] == 'true'

      # These three fields are optional in the XSD.
      vuln.published = Date::parse(xml.attributes['published']) if xml.attributes['published']
      vuln.cvss_vector = xml.attributes['cvssVector'] if xml.attributes['cvssVector']
      vuln.cvss_score = xml.attributes['cvssScore'].to_f if xml.attributes['cvssScore']
      vuln
    end

    def self.parse(xml)
      parse_attributes(xml)
    end
  end

  # Details for a vulnerability.
  #
  class VulnerabilityDetail < VulnerabilitySummary

    # The HTML Description of this vulnerability.
    attr_accessor :description

    # External References for this vulnerability.
    # Array containing (Reference)
    attr_accessor :references

    # The HTML Solution for this vulnerability.
    attr_accessor :solution

    def initialize(id, title, severity)
      @id, @title, @severity = id, title, severity
      @references = []
    end

    def self.parse(xml)
      vuln = parse_attributes(xml)

      vuln.description = REXML::XPath.first(xml, 'description').text
      vuln.solution = REXML::XPath.first(xml, 'solution').text

      xml.elements.each('references/reference') do |ref|
        vuln.references << Reference.new(ref.attributes['source'], ref.text)
      end
      vuln
    end
  end

  # Reference information for a Vulnerability.
  #
  class Reference

    attr_reader :source
    attr_reader :reference

    def initialize(source, reference)
      @source = source
      @reference = reference
    end
  end

  module NexposeAPI
    include XMLUtils

    ###################
    # VULN EXCEPTIONS #
    ###################

    #-----------------------------------------------------------------------
    # Returns an array of vulnerability exceptions and their associated
    # attributes.
    #
    # @param status - (optional) The status of the vulnerability exception:
    # "Under Review", "Approved", "Rejected"
    #-----------------------------------------------------------------------
    def vuln_exception_listing(status = nil)
      option = {}

      if status && !status.empty?
        if status =~ /Under Review|Approved|Rejected/
          option['status'] = status
        else
          raise ArgumentError.new 'The vulnerability status passed in is invalid!'
        end
      end

      xml = make_xml('VulnerabilityExceptionListingRequest', option)
      r = execute xml, '1.2'

      if r.success
        res = []
        r.res.elements.each('//VulnerabilityException') do |ve|
          submitter_comment = ve.elements['submitter-comment']
          reviewer_comment = ve.elements['reviewer-comment']
          res << {
            :vuln_id => ve.attributes['vuln-id'],
            :exception_id => ve.attributes['exception-id'],
            :submitter => ve.attributes['submitter'],
            :reviewer => ve.attributes['reviewer'],
            :status => ve.attributes['status'],
            :reason => ve.attributes['reason'],
            :scope => ve.attributes['scope'],
            :device_id => ve.attributes['device-id'],
            :port_no => ve.attributes['port-no'],
            :expiration_date => ve.attributes['expiration-date'],
            :vuln_key => ve.attributes['vuln-key'],
            :submitter_comment => submitter_comment.nil? ? '' : submitter_comment.text,
            :reviewer_comment => reviewer_comment.nil? ? '' : reviewer_comment.text
          }
        end
        res
      else
        false
      end
    end

    #-------------------------------------------------------------------------------------------------------------------
    # Creates a vulnerability exception.
    #
    # @param input - data used to create the vulnerability exception:
    # :vuln_id - The Nexpose vulnerability ID.
    # :reason - The reason for the exception
    #         values - "False Positive", "Compensating Control", "Acceptable Use", "Acceptable Risk", "Other"
    # :scope - The scope type  (NOTE: The case is important)
    #        values - "All Instances", "All Instances on a Specific Asset", "Specific Instance of a specific Asset"
    # :comment - A user comment
    # :device-id - Used for specific instances related to "All Instances on a Specific Asset" AND "Specific Instance of Specific Asset"
    # :port - All assets on this port related to "Specific Instance of a specific Asset"
    # :vuln-key - The vulnerability key related to the "Specific Instance of a specific Asset"
    #
    # @returns exception-id - The Id associated with this create request
    #-------------------------------------------------------------------------------------------------------------------
    def vuln_exception_create(input)
      options = {}

      if input.nil?
        raise ArgumentError.new 'The input element cannot be null'
      end

      vuln_id = input[:vuln_id]
      unless vuln_id
        raise ArgumentError.new 'The vulnerability ID is required'
      end
      options['vuln-id'] = vuln_id

      reason = input[:reason]
      if reason.nil? || reason.empty?
        raise ArgumentError.new 'The reason is required'
      end

      unless reason =~ /False Positive|Compensating Control|Acceptable Use|Acceptable Risk|Other/
        raise ArgumentError.new 'The reason type is invalid'
      end
      options['reason'] = reason

      scope = input[:scope]
      if scope.nil? || scope.empty?
        raise ArgumentError.new 'The scope is required'
      end

      # For scope case matters.
      unless scope =~ /All Instances|All Instances on a Specific Asset|Specific Instance of Specific Asset/
        raise ArgumentError.new 'The scope type is invalid'
      end

      if scope =~ /All Instances on a Specific Asset|Specific Instance of Specific Asset/
        device_id = input[:device_id]
        vuln_key = input[:vuln_key]
        port = input[:port]
        if device_id
          options['device-id'] = device_id
        end

        if scope =~ /All Instances on a Specific Asset/ && (vuln_key || port)
          raise ArgumentError.new 'Vulnerability key or port cannot be used with the scope specified'
        end

        if vuln_key
          options['vuln-key'] = vuln_key
        end

        if port
          options['port-no'] = port
        end
      end
      options['scope'] = scope

      xml = make_xml('VulnerabilityExceptionCreateRequest', options)

      comment = input[:comment]
      if comment && !comment.empty?
        comment_xml = make_xml('comment', {}, comment, false)
        xml.add_element comment_xml
      else
        raise ArgumentError.new 'The comment cannot be empty'
      end

      r = execute xml, '1.2'
      if r.success
        r.res.elements.each('//VulnerabilityExceptionCreateResponse') do |vecr|
          return vecr.attributes['exception-id']
        end
      else
        false
      end
    end

    #-------------------------------------------------------------------------------------------------------------------
    # Resubmit a vulnerability exception.
    #
    # @param input - data used to create the vulnerability exception:
    # :vuln_id - The Nexpose vulnerability ID. (required)
    # :reason - The reason for the exception (optional)
    #         values - "False Positive", "Compensating Control", "Acceptable Use", "Acceptable Risk", "Other"
    # :comment - A user comment  (required)
    #-------------------------------------------------------------------------------------------------------------------
    def vuln_exception_resubmit(input)
      options = {}

      if input.nil?
        raise ArgumentError.new 'The input element cannot be null'
      end

      exception_id = input[:exception_id]
      unless exception_id
        raise ArgumentError.new 'The exception ID is required'
      end
      options['exception-id'] = exception_id

      reason = input[:reason]
      if !reason.nil? && !reason.empty?
        unless reason =~ /False Positive|Compensating Control|Acceptable Use|Acceptable Risk|Other/
          raise ArgumentError.new 'The reason type is invalid'
        end
        options['reason'] = reason

      end

      xml = make_xml('VulnerabilityExceptionResubmitRequest', options)

      comment = input[:comment]
      if comment && !comment.empty?
        comment_xml = make_xml('comment', {}, comment, false)
        xml.add_element comment_xml
      end

      r = execute xml, '1.2'
      r.success
    end

    #-------------------------------------------------------------------------------------------------------------------
    # Allows a previously submitted exception that has not been approved to be withdrawn.
    #
    # @param exception_id - The exception id returned after the vuln exception was submitted for creation.
    #-------------------------------------------------------------------------------------------------------------------
    def vuln_exception_recall(exception_id)
      xml = make_xml('VulnerabilityExceptionRecallRequest', {'exception-id' => exception_id})
      r = execute xml, '1.2'
      r.success
    end


    #-------------------------------------------------------------------------------------------------------------------
    # Allows a submitted vulnerability exception to be approved.
    #
    # @param input:
    # :exception_id - The exception id returned after the vuln exception was submitted for creation.
    # :comment - An optional comment
    #-------------------------------------------------------------------------------------------------------------------
    def vuln_exception_approve(input)
      exception_id = input[:exception_id]
      unless exception_id
        raise ArgumentError.new 'Exception Id is required'
      end

      xml = make_xml('VulnerabilityExceptionApproveRequest', {'exception-id' => exception_id})
      comment = input[:comment]
      if comment && !comment.empty?
        comment_xml = make_xml('comment', {}, comment, false)
        xml.add_element comment_xml
      end

      r = execute xml, '1.2'
      r.success
    end

    #-------------------------------------------------------------------------------------------------------------------
    # Rejects a submitted vulnerability exception to be approved.
    #
    # @param input:
    # :exception_id - The exception id returned after the vuln exception was submitted for creation.
    # :comment - An optional comment
    #-------------------------------------------------------------------------------------------------------------------
    def vuln_exception_reject(input)
      exception_id = input[:exception_id]
      unless exception_id
        raise ArgumentError.new 'Exception Id is required'
      end

      xml = make_xml('VulnerabilityExceptionRejectRequest', {'exception-id' => exception_id})
      comment = input[:comment]
      if comment && !comment.empty?
        comment_xml = make_xml('comment', {}, comment, false)
        xml.add_element comment_xml
      end

      r = execute xml, '1.2'
      r.success
    end

    #-------------------------------------------------------------------------------------------------------------------
    # Updates a vulnerability exception comment.
    #
    # @param input:
    # :exception_id - The exception id returned after the vuln exception was submitted for creation.
    # :submitter_comment - The submitter comment
    # :reviewer_comment - The reviewer comment
    #-------------------------------------------------------------------------------------------------------------------
    def vuln_exception_update_comment(input)
      exception_id = input[:exception_id]
      unless exception_id
        raise ArgumentError.new 'Exception Id is required'
      end

      xml = make_xml('VulnerabilityExceptionUpdateCommentRequest', {'exception-id' => exception_id})
      submitter_comment = input[:submitter_comment]
      if submitter_comment && !submitter_comment.empty?
        comment_xml = make_xml('submitter-comment', {}, submitter_comment, false)
        xml.add_element comment_xml
      end

      reviewer_comment = input[:reviewer_comment]
      if reviewer_comment && !reviewer_comment.empty?
        comment_xml = make_xml('reviewer-comment', {}, reviewer_comment, false)
        xml.add_element comment_xml
      end

      r = execute xml, '1.2'
      r.success
    end

    #-------------------------------------------------------------------------------------------------------------------
    # Update the expiration date for a vulnerability exception.
    #
    # @param input
    # :exception_id - The exception id returned after the vulnerability exception was submitted for creation.
    # :expiration_date - The new expiration date format: YYYY-MM-DD
    #-------------------------------------------------------------------------------------------------------------------
    def vuln_exception_update_expiration_date(input)
      exception_id = input[:exception_id]
      unless exception_id
        raise ArgumentError.new 'Exception Id is required'
      end

      expiration_date = input[:expiration_date]
      if expiration_date && !expiration_date.empty? && expiration_date =~ /\A\d{4}-(\d{2})-(\d{2})\z/
        if $1.to_i > 12
          raise ArgumentError.new 'The expiration date month value is invalid'
        end
        if $2.to_i > 31
          raise ArgumentError.new 'The expiration date day value is invalid'
        end
      else
        raise ArgumentError.new 'Expiration date is invalid'
      end

      options = {}
      options['exception-id'] = exception_id
      options['expiration-date'] = expiration_date
      xml = make_xml('VulnerabilityExceptionUpdateExpirationDateRequest', options)
      r = execute xml, '1.2'
      r.success
    end

    #-------------------------------------------------------------------------------------------------------------------
    # Deletes a submitted vulnerability exception to be approved.
    #
    # @param exception_id - The exception id returned after the vuln exception was submitted for creation.
    #-------------------------------------------------------------------------------------------------------------------
    def vuln_exception_delete(exception_id)
      unless exception_id
        raise ArgumentError.new 'Exception Id is required'
      end

      xml = make_xml('VulnerabilityExceptionDeleteRequest', {'exception-id' => exception_id})
      r = execute xml, '1.2'
      r.success
    end
  end
end
