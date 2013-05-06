module Nexpose

  module Ticket

    module State
      OPEN = 'O'
      ASSIGNED = 'A'
      MODIFIED = 'M'
      FIXED = 'X'
      PARTIAL = 'P'
      REJECTED_FIX = 'R'
      PRIORITIZED = 'Z'
      NOT_REPRODUCIBLE = 'F'
      NOT_ISSUE = 'I'
      CLOSED = 'C'
      UNKNOWN = 'U'
    end

    module Priority
      LOW = 'low'
      MODERATE = 'moderate'
      NORMAL = 'normal'
      HIGH = 'high'
      CRITICAL = 'critical'
    end
  end

  module NexposeAPI
    include XMLUtils

    def ticket_listing
      xml = make_xml('TicketListingRequest')
      r = execute(xml, '1.2')
      tickets = []
      if r.success
        r.res.elements.each('TicketListingResponse/TicketSummary') do |summary|
          tickets << TicketSummary::parse(summary)
        end
      end
      tickets
    end

    alias_method :tickets, :ticket_listing

    # Deletes a Nexpose ticket.
    #
    # @param [Fixnum] ticket Unique ID of the ticket to delete.
    # @return [Boolean] Whether or not the ticket deletion succeeded.
    #
    def delete_ticket(ticket)
      delete_tickets([ticket])
    end

    # Deletes a Nexpose ticket.
    #
    # @param [Array[Fixnum]] tickets Array of unique IDs of tickets to delete.
    # @return [Boolean] Whether or not the ticket deletions succeeded.
    #
    def delete_tickets(tickets)
      xml = make_xml('TicketDeleteRequest')
      tickets.each do |id|
        xml.add_element('Ticket', {'id' => id})
      end

      (execute xml, '1.2').success
    end

    alias_method :ticket_delete, :delete_tickets

    #
    # Create a Nexpose ticket
    #
    # ticket_info: A hash of the data to be used to create a ticket in Nexpose:
    # :name        => The name of the ticket (Required)
    # :device_id   => The Nexpose device ID for the device being ticketed (Required)
    # :assigned_to => The Nexpose user to whom this ticket is assigned (Required)
    # :priority    => "low,moderate,normal,high,critical" (Required)
    #
    # :vulnerabilities => An array of Nexpose vuln IDs. This is NOT the same as vuln ID.  (Required)
    # :comments        => An array of comments to accompany this ticket
    #
    # @return The ticket ID if the ticket creation was successful, {@code false} otherwise
    #
    def create_ticket(ticket_info)
      ticket_name = ticket_info[:name]
      unless ticket_name
        raise ArgumentError.new 'Ticket name is required'
      end

      device_id = ticket_info[:device_id]
      unless device_id
        raise ArgumentError.new 'Device ID is required'
      end

      assigned_to = ticket_info[:assigned_to]
      unless assigned_to
        raise ArgumentError.new 'Assignee name is required'
      end

      priority = ticket_info[:priority]
      unless priority
        raise ArgumentError.new 'Ticket priority is required'
      end

      vulnerabilities = ticket_info[:vulnerabilities]
      if not vulnerabilities or vulnerabilities.count < 1
        raise ArgumentError.new 'Vulnerabilities are required'
      end

      comments = ticket_info[:comments]
      base_xml = make_xml 'TicketCreateRequest'

      required_attributes = {
          'name' => ticket_name,
          'priority' => priority,
          'device-id' => device_id,
          'assigned-to' => assigned_to
      }

      create_request_xml = REXML::Element.new 'TicketCreate'
      create_request_xml.add_attributes required_attributes

      # Add vulnerabilities
      vulnerabilities_xml = REXML::Element.new 'Vulnerabilities'
      vulnerabilities.each do |vuln_id|
        vulnerabilities_xml.add_element 'Vulnerability', {'id' => vuln_id}
      end
      create_request_xml.add_element vulnerabilities_xml

      # Add comments
      if comments and comments.count > 0
        comments_xml = REXML::Element.new 'Comments'
        comments.each do |comment|
          comment_xml = REXML::Element.new 'Comment'
          comment_xml.add_text comment
          comments_xml.add_element comment_xml
        end

        create_request_xml.add_element comments_xml
      end

      base_xml.add_element create_request_xml
      r = execute base_xml, '1.2'
      if r.success
        r.res.elements.each('TicketCreateResponse') do |group|
          return group.attributes['id'].to_i
        end
      else
        false
      end
    end
  end

  # Summary of ticket information returned from a ticket listing request.
  # For more details, issue a ticket detail request.
  #
  class TicketSummary

    # The ID number of the ticket.
    attr_accessor :id

    # Ticket name.
    attr_accessor :name

    # The asset the ticket is created for.
    attr_accessor :device_id

    # The login name of person to whom the ticket is assigned.
    # The user must have view asset privilege on the asset specified in the device-id attribute.
    attr_accessor :assigned_to

    # The relative priority of the ticket, assigned by the creator of the ticket.
    # @see Nexpose::Ticket::Priority
    attr_accessor :priority

    # The login name of the person who created the ticket.
    attr_accessor :author

    # Date and time of ticket creation.
    attr_accessor :created_on

    # The current status of the ticket.
    attr_accessor :state

    def initialize(id, name)
      @id, @name = id, name
    end

    def self.parse(xml)
      ticket = new(xml.attributes['id'].to_i,
                   xml.attributes['name'])
      ticket.device_id = xml.attributes['device-id'].to_i
      ticket.assigned_to = xml.attributes['assigned-to']
      ticket.priority = xml.attributes['priority']
      ticket.author = xml.attributes['author']
      ticket.created_on = DateTime::parse(xml.attributes['created-on'])
      lookup = Ticket::State.constants.reduce({}) { |a, e| a[Ticket::State.const_get(e)] = e; a }
      ticket.state = lookup[xml.attributes['state']]
      ticket
    end
  end
end
