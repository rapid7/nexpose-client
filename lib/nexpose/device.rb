module Nexpose
  module NexposeAPI
    include XMLUtils

    # Find a Device by its address.
    #
    # This is a convenience method for finding a single device from a SiteDeviceListing.
    # If no site_id is provided, the first matching device will be returned when a device
    # occurs across multiple sites.
    #
    # @param [String] address Address of the device to find. Usually the IP address.
    # @param [FixNum] site_id Site ID to restrict search to.
    # @return [Device] The first matching Device with the provided address,
    #   if found.
    #
    def find_device_by_address(address, site_id = nil)
      r = execute(make_xml('SiteDeviceListingRequest', {'site-id' => site_id}))
      if r.success
        device = REXML::XPath.first(r.res, "SiteDeviceListingResponse/SiteDevices/device[@address='#{address}']")
        return Device.new(device.attributes['id'].to_i,
                          device.attributes['address'],
                          device.parent.attributes['site-id'],
                          device.attributes['riskfactor'].to_f,
                          device.attributes['riskscore'].to_f) if device
      end
      nil
    end

    # Retrieve a list of all of the assets in a site.
    #
    # If no site-id is specified, then return all of the assets
    # for the Nexpose console, grouped by site-id.
    #
    # @param [FixNum] site_id Site ID to request device listing for. Optional.
    # @return [Array[Device]] Array of devices associated with the site, or
    #   all devices on the console if no site is provided.
    #
    def list_site_devices(site_id = nil)
      r = execute(make_xml('SiteDeviceListingRequest', {'site-id' => site_id}))

      devices = []
      if r.success
        r.res.elements.each('SiteDeviceListingResponse/SiteDevices') do |site|
          site_id = site.attributes['site-id'].to_i
          site.elements.each('device') do |device|
            devices << Device.new(device.attributes['id'].to_i,
                                  device.attributes['address'],
                                  site_id,
                                  device.attributes['riskfactor'].to_f,
                                  device.attributes['riskscore'].to_f)
          end
        end
      end
      devices
    end

    alias_method :devices, :list_site_devices
    alias_method :list_devices, :list_site_devices
    alias_method :assets, :list_site_devices
    alias_method :list_assets, :list_site_devices

    # List the vulnerability findings for a given device ID.
    #
    # @param [Fixnum] dev_id Unique identifier of a device (asset).
    # @return [Array[Vulnerability]] List of vulnerability findings.
    #
    def list_device_vulns(dev_id)
      raw = DataTable._get_dyn_table(self, "/ajax/device_vulns.txml?devid=#{dev_id}")
      raw.map { |vuln| VulnFinding.new(vuln) }
    end

    def delete_device(device_id)
      r = execute(make_xml('DeviceDeleteRequest', {'device-id' => device_id}))
      r.success
    end
  end

  # Object that represents a single device in a Nexpose security console.
  #
  class Device

    # A unique device ID (assigned automatically by the Nexpose console).
    attr_reader :id
    # IP Address or Hostname of this device.
    attr_reader :address
    # User assigned risk multiplier.
    attr_reader :risk_factor
    # Nexpose risk score.
    attr_reader :risk_score
    # Site ID that this device is associated with.
    attr_reader :site_id

    def initialize(id, address, site_id, risk_factor = 1.0, risk_score = 0.0)
      @id = id.to_i
      @address = address
      @site_id = site_id.to_i
      @risk_factor = risk_factor.to_f
      @risk_score = risk_score.to_f
    end
  end
end
