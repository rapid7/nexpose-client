module Nexpose
  module NexposeAPI
    include XMLUtils

    # Retrieve vulnerability exceptions.
    #
    # @param [String] status Filter exceptions by the current status.
    #   @see Nexpose::VulnException::Status
    # @param [String] duration A time interval in the format "PnYnMnDTnHnMnS".
    # @return [Array[VulnException]] List of matching vulnerability exceptions.
    #
    def list_vuln_exceptions(status = nil, duration = nil)
      option = {}
      option['status'] = status if status
      option['time-duration'] = duration if duration
      xml = make_xml('VulnerabilityExceptionListingRequest', option)
      response = execute(xml, '1.2')

      xs = []
      if response.success
        response.res.elements.each('//VulnerabilityException') do |ve|
          xs << VulnException.parse(ve)
        end
        res
      end
      xs
    end

    alias_method :vuln_exceptions, :list_vuln_exceptions
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
    def delete_vuln_exception(exception_id)
      unless exception_id
        raise ArgumentError.new 'Exception Id is required'
      end

      xml = make_xml('VulnerabilityExceptionDeleteRequest', {'exception-id' => exception_id})
      r = execute xml, '1.2'
      r.success
    end
  end

  # In addition to attributes listed as required in the preceding table, certain
  # attributes are necessary for certain exception scopes, even though they are
  # listed as optional.
  # • An exception for all instances of a vulnerability on all assets only
  #   requires the vuln_id attribute. The device_id, vuln_key and port
  #   attributes are ignored for this scope type.
  # • An exception for all instances on a specific asset requires the vuln_id
  #   and device_id attributes. The vuln_key and port attributes are ignored for
  #   this scope type.
  # • An exception for a specific instance of a vulnerability on a specific
  #   asset requires the vuln_id, device_id. Additionally, the port and/or the
  #   key attribute must be specified.
  #
  class VulnException

    # Unique identifier assigned to an exception.
    attr_accessor :id
    # Unique identifier of a vulnerability.
    attr_accessor :vuln_id
    # The name of submitter of the exception.
    attr_accessor :submitter
    # The name of the reviewer of the exception.
    attr_accessor :reviewer
    # The state of the exception in the work flow process.
    # @see Nexpose::VulnException::Status
    attr_accessor :status
    # The reason for the exception status.
    # @see Nexpose::VulnException::Reason
    attr_accessor :reason
    # The scope of the exception.
    # @see Nexpose::VulnException::Scope
    attr_accessor :scope
    # ID of device, if this exception applies to only one device.
    attr_accessor :device_id
    # Port on a device, if this exception applies to a specific port.
    attr_accessor :port
    # The specific vulnerable component in a discovered instance of the
    # vulnerability referenced by the vuln_id, such as a program, file or user
    # account.
    attr_accessor :vuln_key
    # The date an exception will expire, causing the vulnerability to be
    # included in report risk scores.
    attr_accessor :expiration
    # Any comment provided by the submitter.
    attr_accessor :submitter_comment
    # Any comment provided by the reviewer.
    attr_accessor :reviewer_comment

    def initialize(vuln_id, scope, reason, status = nil)
      @vuln_id, @scope, @reason, @status = vuln_id, scope, reason, status
    end

    # Create this exception on the security console.
    #
    # @param [Connection] connection Connection to security console.
    #
    def save(connection, comment = nil)
      validate
      @submitter_comment = comment if comment
      response = execute(to_xml, '1.2')
    end

    def to_xml
      xml = connection.make_xml('VulnerabilityExceptionCreateRequest')
      xml.add_attributes({ 'vuln-id' => @vuln_id,
                           'scope' => @scope,
                           'reason' => @reason })
      case @scope
      when Scope::ALL_INSTANCES_ON_A_SPECIFIC_ASSET
        xml.add_attributes({ 'device-id' => @device_id })
      when Scope::SPECIFIC_INSTANCE_OF_SPECIFIC_ASSET
        xml.add_attributes({ 'device-id' => @device_id,
                             'port-no' => @port,
                             'vuln-key' => @vuln_key })
      end

      if @submitter_comment
        comment = REXML::Element.new('submitter-comment')
        comment.add_text(@submitter_comment)
        xml.add_element(comment)
      end

      xml
    end

    # Validate that this exception meets to requires for the assigned scope.
    #
    def validate
      raise ArgumentError.new('No vuln_id.') unless @vuln_id
      raise ArgumentError.new('No scope.') unless @scope
      raise ArgumentError.new('No reason.') unless @reason

      case @scope
      when Scope::ALL_INSTANCES
        @device_id = @port = @vuln_key = nil
      when Scope::ALL_INSTANCES_ON_A_SPECIFIC_ASSET
        raise ArgumentError.new('No device_id.') unless @device_id
        @port = @vuln_key = nil
      when Scope::SPECIFIC_INSTANCE_OF_SPECIFIC_ASSET
        raise ArgumentError.new('No device_id.') unless @device_id
        raise ArgumentError.new('Port or vuln_key is required.') unless @port or @vuln_key
      else
        raise ArgumentError.new("Invalid scope: #{@scope}")
      end
    end

    def self.parse(xml)
      exception = new(xml.attributes['vuln-id'],
                      xml.attributes['scope'],
                      xml.attributes['reason'],
                      xml.attributes['status'])

      exception.id = xml.attributes['exception-id']
      exception.submitter = xml.attributes['submitter']
      exception.reviewer = xml.attributes['reviewer']
      exception.device_id = xml.attributes['device-id']
      exception.port = xml.attributes['port-no']
      exception.vuln_key = xml.attributes['vuln-key']
      # TODO Convert to Date/Time object.
      exception.expiration = xml.attributes['expiration-date']

      submitter_comment = xml.elements['submitter-comment']
      exception.submitter_comment = submitter_comment.text if submitter_comment
      reviewer_comment = xml.elements['reviewer-comment']
      exception.reviewer_comment = reviewer_comment.text if reviewer_comment

      exception
    end

    # The state of a vulnerability exception in the work flow process.
    #
    module Status
      UNDER_REVIEW = 'Under Review'
      APPROVED = 'Approved'
      REJECTED = 'Rejected'
    end

    # The reason for the exception status.
    #
    module Reason
      FALSE_POSITIVE = 'False Positive'
      COMPENSATING_CONTROL = 'Compensating Control'
      ACCEPTABLE_USE = 'Acceptable Use'
      ACCEPTABLE_RISK = 'Acceptable Risk'
      OTHER = 'Other'
    end

    # The scope of the exception.
    #
    module Scope
      ALL_INSTANCES = 'All Instances'
      ALL_INSTANCES_ON_A_SPECIFIC_ASSET = 'All Instances on a Specific Asset'
      SPECIFIC_INSTANCE_OF_SPECIFIC_ASSET = 'Specific Instance of Specific Asset'
    end
  end
end
