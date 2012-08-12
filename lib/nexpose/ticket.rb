module Nexpose
	module NexposeAPI
		include XMLUtils

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
		def create_ticket ticket_info
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

		#
		# Deletes a Nexpose ticket.
		#
		# ticket_ids: An array of ticket IDs to be deleted.
		#
		# @returns {@code true} iff the call was successfull. {@code false} otherwise.
		#
		def delete_ticket ticket_ids
			if not ticket_ids or ticket_ids.count < 1
				raise ArgumentError.new 'The tickets to delete should not be null or empty'
			end

			base_xml = make_xml 'TicketDeleteRequest'
			ticket_ids.each do |id|
				base_xml.add_element 'Ticket', {'id' => id}
			end

			(execute base_xml, '1.2').success
		end
	end
end
