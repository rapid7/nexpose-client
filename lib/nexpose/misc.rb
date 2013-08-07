module Nexpose
  module NexposeAPI
    include XMLUtils

    def delete_device(device_id)
      r = execute(make_xml('DeviceDeleteRequest', {'device-id' => device_id}))
      r.success
    end
  end
end
