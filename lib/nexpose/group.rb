module Nexpose
  module NexposeAPI
    include XMLUtils

    # Delete an asset group and all associated data.
    #
    # @param [Fixnum] id Asset group ID to delete.
    #
    # @return [Boolean] Whether group deletion succeeded.
    #
    def asset_group_delete(id)
      r = execute(make_xml('AssetGroupDeleteRequest', {'group-id' => id}))
      r.success
    end

    alias_method :delete_asset_group, :asset_group_delete

    # Retrieve a list of all asset groups the user is authorized to view or
    # manage.
    #
    # @return [Array[AssetGroupSummary]] Array of AssetGroupSummary objects.
    #
    def asset_groups
      r = execute(make_xml('AssetGroupListingRequest'))

      res = []
      if r.success
        r.res.elements.each('//AssetGroupSummary') do |group|
          res << AssetGroupSummary.new(group.attributes['id'].to_i,
                                       group.attributes['name'].to_s,
                                       group.attributes['description'].to_s,
                                       group.attributes['riskscore'].to_f)
        end
      end
      res
    end

    alias_method :asset_groups_listing, :asset_groups
  end

  # Summary value object for asset group information.
  #
  class AssetGroupSummary
    attr_reader :id, :name, :description, :risk_score

    def initialize(id, name, desc, risk)
      @id, @name, @description, @risk_score = id, name, desc, risk
    end

    # Delete this asset group and all associated data.
    #
    # @param [Connection] connection Connection to security console.
    #
    def delete(connection)
      connection.asset_group_delete(@id)
    end
  end

  # Asset group configuration object containing Device details.
  #
  class AssetGroup < AssetGroupSummary

    # Array[Device] of devices associated with this asset group.
    attr_accessor :devices

    def initialize(id, name, desc, risk)
      @id, @name, @description, @risk_score = id, name, desc, risk
      @devices = []
    end

    # Launch adhoc scans against each group of assets per site.
    #
    # @param [Connection] connection Connection to console where asset group is configured.
    # @return [Array[Hash[Fixnum, Fixnum]]] Array of scan ID and engine ID
    #   pairs for each scan launched.
    #
    def rescan_assets(connection)
      sites_ids = @devices.collect { |d| d.site_id }.uniq
      scans = []
      sites_ids.each do |id|
        dev_ids = @devices.select { |d| d.site_id == id }.map { |d| d.id }
        scans << connection.site_device_scan_start(id, dev_ids).merge(:site_id => id)
      end
      scans
    end

    # Load an existing configuration from a Nexpose instance.
    #
    # @param [Connection] connection Connection to console where asset group is configured.
    # @param [Fixnum] id Asset group ID of an existing group.
    # @return [AssetGroup] Asset group configuration loaded from a Nexpose console.
    #
    def self.load(connection, id)
      r = APIRequest.execute(connection.url,
                             %Q(<AssetGroupConfigRequest session-id="#{connection.session_id}" group-id="#{id}"/>))
      parse(r.res)
    end

    def self.parse(rexml)
      return nil unless rexml

      rexml.elements.each('//AssetGroup') do |group|
        asset_group = new(group.attributes['id'].to_i,
                          group.attributes['name'].to_s,
                          group.attributes['description'].to_s,
                          group.attributes['riskscore'].to_f)
        rexml.elements.each('//Devices/device') do |dev|
          asset_group.devices << Device.new(dev.attributes['id'].to_i,
                                            dev.attributes['address'].to_s,
                                            dev.attributes['site-id'].to_i,
                                            dev.attributes['riskfactor'].to_f,
                                            dev.attributes['riskscore'].to_f)
        end
        return asset_group
      end
    end
  end
end
