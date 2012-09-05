module Nexpose
  module NexposeAPI
    include XMLUtils

    ###################
    # SILO MANAGEMENT #
    ###################

    #########################
    # MULTI-TENANT USER OPS #
    #########################

    #-------------------------------------------------------------------------
    # Creates a multi-tenant user
    #
    # user_config - A map of the user data.
    #
    # REQUIRED PARAMS
    # user-id, authsrcid, user-name, full-name, enabled, superuser
    #
    # OPTIONAL PARAMS
    # email, password
    #
    # silo_configs - An array of maps of silo specific data
    #
    # REQUIRED PARAMS
    # silo-id, role-name, all-groups, all-sites, default-silo
    #
    # allowed_groups/allowed_sites - An array of ids
    #-------------------------------------------------------------------------
    def create_multi_tenant_user(user_config, silo_configs)
      xml = make_xml('MultiTenantUserCreateRequest')
      mtu_config_xml = make_xml('MultiTenantUserConfig', user_config, '', false)

      # Add the silo access
      silo_xml = make_xml('SiloAccesses', {}, '', false)
      silo_configs.each do |silo_config|
        silo_config_xml = make_xml('SiloAccess', {}, '', false)
        silo_config.keys.each do |k|
          if k == 'allowed_sites'
            allowed_sites_xml = make_xml('AllowedSites', {}, '', false)
            silo_config['allowed_sites'].each do |allowed_site|
              allowed_sites_xml.add_element(make_xml('AllowedSite', {'id' => allowed_site}, '', false))
            end
            silo_config_xml.add_element(allowed_sites_xml)
          elsif k == 'allowed_groups'
            allowed_groups_xml = make_xml('AllowedGroups', {}, '', false)
            silo_config['allowed_groups'].each do |allowed_group|
              allowed_groups_xml.add_element(make_xml('AllowedGroup', {'id' => allowed_group}, '', false))
            end
            silo_config_xml.add_element(allowed_groups_xml)
          else
            silo_config_xml.attributes[k] = silo_config[k]
          end
        end
        silo_xml.add_element(silo_config_xml)
      end
      mtu_config_xml.add_element(silo_xml)
      xml.add_element(mtu_config_xml)
      r = execute(xml, '1.2')
      r.success
    end

    #-------------------------------------------------------------------------
    # Lists all the multi-tenant users and their attributes.
    #-------------------------------------------------------------------------
    def list_mtu
      xml = make_xml('MultiTenantUserListingRequest')
      r = execute xml, '1.2'

      if r.success
        res = []
        r.res.elements.each("//MultiTenantUserSummary") do |mtu|
          res << {
            :id => mtu.attributes['id'],
            :full_name => mtu.attributes['full-name'],
            :user_name => mtu.attributes['user-name'],
            :email => mtu.attributes['email'],
            :super_user => mtu.attributes['superuser'],
            :enabled => mtu.attributes['enabled'],
            :auth_module => mtu.attributes['auth-module'],
            :silo_count => mtu.attributes['silo-count'],
            :locked => mtu.attributes['locked']
          }
        end
        res
      else
        false
      end
    end

    #-------------------------------------------------------------------------
    # Delete a multi-tenant user
    #-------------------------------------------------------------------------
    def delete_mtu user_name, user_id
      using_user_name = (user_name and not user_name.empty?)
      xml = make_xml('MultiTenantUserDeleteRequest', (using_user_name ? {'user-name' => user_name} : {'user-id' => user_id}))
      r = execute xml, '1.2'
      r.success
    end

    ####################
    # SILO PROFILE OPS #
    ####################

    #-------------------------------------------------------------------------
    # Creates a silo profile
    #
    # silo_config - A map of the silo data.
    #
    # REQUIRED PARAMS
    # id, name, all‐licensed-modules, all‐global-engines, all-global-report-templates, all‐global-scan‐templates
    #
    # OPTIONAL PARAMS
    # description
    #
    # permissions - A map of an array of maps of silo specific data
    #
    # REQUIRED PARAMS
    # silo-id, role-name, all-groups, all-sites, default-silo
    #
    # allowed_groups/allowed_sites - An array of ids
    #-------------------------------------------------------------------------
    def create_silo_profile silo_profile_config, permissions
      xml = make_xml 'SiloProfileCreateRequest'
      spc_xml = make_xml('SiloProfileConfig', silo_profile_config, '', false)

      # Add the permissions
      if permissions['global_report_templates']
        grt_xml = make_xml('GlobalReportTemplates', {}, '', false)
        permissions['global_report_templates'].each do |name|
          grt_xml.add_element make_xml('GlobalReportTemplate', {'name' => name}, '', false)
        end
        spc_xml.add_element grt_xml
      end

      if permissions['global_scan_engines']
        gse_xml = make_xml('GlobalScanEngines', {}, '', false)
        permissions['global_scan_engines'].each do |name|
          gse_xml.add_element make_xml('GlobalScanEngine', {'name' => name}, '', false)
        end
        spc_xml.add_element gse_xml
      end

      if permissions['global_scan_templates']
        gst_xml = make_xml('GlobalScanTemplates', {}, '', false)
        permissions['global_scan_templates'].each do |name|
          gst_xml.add_element make_xml('GlobalScanTemplate', {'name' => name}, '', false)
        end
        spc_xml.add_element gst_xml
      end

      if permissions['licensed_modules']
        lm_xml = make_xml('LicensedModules', {}, '', false)
        permissions['licensed_modules'].each do |name|
          lm_xml.add_element make_xml('LicensedModule', {'name' => name}, '', false)
        end
        spc_xml.add_element lm_xml
      end

      if permissions['restricted_report_formats']
        rrf_xml = make_xml('RestrictedReportFormats', {}, '', false)
        permissions['restricted_report_formats'].each do |name|
          rrf_xml.add_element make_xml('RestrictedReportFormat', {'name' => name}, '', false)
        end
        spc_xml.add_element rrf_xml
      end

      if permissions['restricted_report_sections']
        rrs_xml = make_xml('RestrictedReportSections', {}, '', false)
        permissions['restricted_report_sections'].each do |name|
          rrs_xml.add_element make_xml('RestrictedReportSection', {'name' => name}, '', false)
        end
        spc_xml.add_element rrs_xml
      end

      xml.add_element spc_xml
      r = execute xml, '1.2'
      r.success
    end

    #-------------------------------------------------------------------------
    # Lists all the silo profiles and their attributes.
    #-------------------------------------------------------------------------
    def list_silo_profiles
      xml = make_xml('SiloProfileListingRequest')
      r = execute xml, '1.2'

      if r.success
        res = []
        r.res.elements.each("//SiloProfileSummary") do |silo_profile|
          res << {
            :id => silo_profile.attributes['id'],
            :name => silo_profile.attributes['name'],
            :description => silo_profile.attributes['description'],
            :global_report_template_count => silo_profile.attributes['global-report-template-count'],
            :global_scan_engine_count => silo_profile.attributes['global-scan-engine-count'],
            :global_scan_template_count => silo_profile.attributes['global-scan-template-count'],
            :licensed_module_count => silo_profile.attributes['licensed-module-count'],
            :restricted_report_section_count => silo_profile.attributes['restricted-report-section-count'],
            :all_licensed_modules => silo_profile.attributes['all-licensed-modules'],
            :all_global_engines => silo_profile.attributes['all-global-engines'],
            :all_global_report_templates => silo_profile.attributes['all-global-report-templates'],
            :all_global_scan_templates => silo_profile.attributes['all-global-scan-templates']
          }
        end
        res
      else
        false
      end
    end

    #-------------------------------------------------------------------------
    # Delete a silo profile
    #-------------------------------------------------------------------------
    def delete_silo_profile name, id
      using_name = (name and not name.empty?)
      xml = make_xml('SiloProfileDeleteRequest', (using_name ? {'name' => name} : {'silo-profile-id' => id}))
      r = execute xml, '1.2'
      r.success
    end

    ####################
    # SILO OPS #
    ####################

    #-------------------------------------------------------------------------
    # Creates a silo
    #
    # silo_config - A map of the silo creation data.
    #
    # REQUIRED PARAMS
    # id, name, silo-profile-id, max-assets, max-hosted-assets, max-users
    #
    # OPTIONAL PARAMS
    # description
    #-------------------------------------------------------------------------
    def create_silo silo_config
      xml = make_xml 'SiloCreateRequest'
      silo_config_xml = make_xml 'SiloConfig', {}, '', false

      # Add the attributes
      silo_config.keys.each do |key|
        if not 'merchant'.eql? key and not 'organization'.eql? key
          silo_config_xml.attributes[key] = silo_config[key]
        end
      end

      # Add Organization info
      if silo_config['organization']
        org_xml = make_xml 'Organization', {}, '', false
        silo_config['organization'].keys.each do |key|
          if not 'address'.eql? key
            org_xml.attributes[key] = silo_config['organization'][key]
          end
        end

        address_xml = make_xml 'Address', silo_config['organization']['address'], '', false
        org_xml.add_element address_xml
        silo_config_xml.add_element org_xml
      end

      # Add Merchant info
      if silo_config['merchant']
        merchant_xml = make_xml 'Merchant', {}, '', false

        silo_config['merchant'].keys.each do |key|
          if not 'dba'.eql? key and not 'other_industries'.eql? key and not 'qsa'.eql? key and not 'address'.eql? key
            merchant_xml.attributes[key] = silo_config['merchant'][key]
          end
        end

        # Add the merchant address
        merchant_address_xml = make_xml 'Address', silo_config['merchant']['address'], '', false
        merchant_xml.add_element merchant_address_xml

        #Now add the complex data types
        if silo_config['merchant']['dba']
          dba_xml = make_xml 'DBAs', {}, '', false
          silo_config['merchant']['dba'].each do |name|
            dba_xml.add_element make_xml('DBA', {'name' => name}, '', false)
          end
          merchant_xml.add_element dba_xml
        end

        if silo_config['merchant']['other_industries']
          ois_xml = make_xml 'OtherIndustries', {}, '', false
          silo_config['merchant']['other_industries'].each do |name|
            ois_xml.add_element make_xml('Industry', {'name' => name}, '', false)
          end
          merchant_xml.add_element ois_xml
        end

        if silo_config['merchant']['qsa']
          qsa_xml = make_xml 'QSA', {}, '', false
          silo_config['merchant']['qsa'].keys.each do |key|
            if not 'address'.eql? key
              qsa_xml.attributes[key] = silo_config['merchant']['qsa'][key]
            end
          end

          # Add the address for this QSA
          address_xml = make_xml 'Address', silo_config['merchant']['qsa']['address'], '', false

          qsa_xml.add_element address_xml
          merchant_xml.add_element qsa_xml
        end
        silo_config_xml.add_element merchant_xml
      end

      xml.add_element silo_config_xml
      r = execute xml, '1.2'
      r.success
    end

    #-------------------------------------------------------------------------
    # Lists all the silos and their attributes.
    #-------------------------------------------------------------------------
    def list_silos
      xml = make_xml('SiloListingRequest')
      r = execute xml, '1.2'

      if r.success
        res = []
        r.res.elements.each("//SiloSummary") do |silo_profile|
          res << {
            :id => silo_profile.attributes['id'],
            :name => silo_profile.attributes['name'],
            :description => silo_profile.attributes['description']
          }
        end
        res
      else
        false
      end
    end

    #-------------------------------------------------------------------------
    # Delete a silo
    #-------------------------------------------------------------------------
    def delete_silo name, id
      using_name = (name and not name.empty?)
      xml = make_xml('SiloDeleteRequest', (using_name ? {'silo-name' => name} : {'silo-id' => id}))
      r = execute xml, '1.2'
      r.success
    end
  end
end
