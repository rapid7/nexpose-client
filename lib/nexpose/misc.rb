module Nexpose
  module NexposeAPI
    include XMLUtils

    def device_delete(param)
      r = execute(make_xml('DeviceDeleteRequest', {'device-id' => param}))
      r.success
    end

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
  end
end
