module Nexpose
  module NexposeAPI
    include XMLUtils

    #-----------------------------------------------------------------------
    # Returns an array of vulnerability exceptions and their associated
    # attributes.
    #
    # @param status - (optional) The status of the vulnerability exception:
    # "Under Review", "Approved", "Rejected"
    #-----------------------------------------------------------------------
    def list_vuln_exceptions(status = nil)
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
    def delete_vuln_exception(exception_id)
      unless exception_id
        raise ArgumentError.new 'Exception Id is required'
      end

      xml = make_xml('VulnerabilityExceptionDeleteRequest', {'exception-id' => exception_id})
      r = execute xml, '1.2'
      r.success
    end
  end
end
