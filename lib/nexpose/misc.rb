module Nexpose
	module NexposeAPI
		include XMLUtils

		def device_delete(param)
			r = execute(make_xml('DeviceDeleteRequest', {'device-id' => param}))
			r.success
		end

		def asset_group_delete(connection, id, debug = false)
			r = execute(make_xml('AssetGroupDeleteRequest', {'group-id' => param}))
			r.success
		end

		#-------------------------------------------------------------------------
		# Returns all asset group information
		#-------------------------------------------------------------------------
		def asset_groups_listing()
			r = execute(make_xml('AssetGroupListingRequest'))

			if r.success
				res = []
				r.res.elements.each('//AssetGroupSummary') do |group|
					res << {
						:asset_group_id => group.attributes['id'].to_i,
						:name => group.attributes['name'].to_s,
						:description => group.attributes['description'].to_s,
						:risk_score => group.attributes['riskscore'].to_f,
					}
				end
				res
			else
				false
			end
		end

		#-------------------------------------------------------------------------
		# Returns an asset group configuration information for a specific group ID
		#-------------------------------------------------------------------------
		def asset_group_config(group_id)
			r = execute(make_xml('AssetGroupConfigRequest', {'group-id' => group_id}))

			if r.success
				res = []
				r.res.elements.each('//Devices/device') do |device_info|
					res << {
						:device_id => device_info.attributes['id'].to_i,
						:site_id => device_info.attributes['site-id'].to_i,
						:address => device_info.attributes['address'].to_s,
						:riskfactor => device_info.attributes['riskfactor'].to_f,
					}
				end
				res
			else
				false
			end
		end

		#
		# Lists all the users for the NSC along with the user details.
		#
		def list_users
			r = execute(make_xml('UserListingRequest'))
			if r.success
				res = []
				r.res.elements.each('//UserSummary') do |user_summary|
					res << {
						:auth_source => user_summary.attributes['authSource'],
						:auth_module => user_summary.attributes['authModule'],
						:user_name => user_summary.attributes['userName'],
						:full_name => user_summary.attributes['fullName'],
						:email => user_summary.attributes['email'],
						:is_admin => user_summary.attributes['isAdmin'].to_s.chomp.eql?('1'),
						:is_disabled => user_summary.attributes['disabled'].to_s.chomp.eql?('1'),
						:site_count => user_summary.attributes['siteCount'],
						:group_count => user_summary.attributes['groupCount']
					}
				end
				res
			else
				false
			end
		end


		def console_command(cmd_string)
			xml = make_xml('ConsoleCommandRequest', {})
			cmd = REXML::Element.new('Command')
			cmd.text = cmd_string
			xml << cmd

			r = execute(xml)

			if (r.success)
				res = ""
				r.res.elements.each("//Output") do |out|
					res << out.text.to_s
				end

				res
			else
				false
			end
		end

		def system_information
			r = execute(make_xml('SystemInformationRequest', {}))

			if (r.success)
				res = {}
				r.res.elements.each("//Statistic") do |stat|
					res[stat.attributes['name'].to_s] = stat.text.to_s
				end

				res
			else
				false
			end
		end

	end
end