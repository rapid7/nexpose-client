module Nexpose

  module NexposeAPI
    include XMLUtils

    # Returns a summary list of all roles.
    def role_listing
      xml = make_xml('RoleListingRequest')
      r = execute(xml, '1.2')
      if r.success
        res = []
        r.res.elements.each('RoleListingResponse/RoleSummary') do |summary|
          res << {
            :id => summary.attributes['id'],
            :name => summary.attributes['name'],
            :full_name => summary.attributes['full-name'],
            :description => summary.attributes['description'],
            :enabled => summary.attributes['enabled'],
            :scope => summary.attributes['scope']
          }
        end
        res
      end
    end
  end

end
