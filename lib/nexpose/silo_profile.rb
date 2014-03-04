module Nexpose

  class Connection
    include XMLUtils

    def list_silo_profiles
      r = execute(make_xml('SiloProfileListingRequest'), '1.2')
      arr = []
      if r.success
        r.res.elements.each('SiloProfileListingResponse/SiloProfileSummaries/SiloProfileSummary') do |profile|
          arr << SiloProfileSummary.parse(profile)
        end
      end
      arr
    end
  end

  class SiloProfile
    attr_accessor :id
    attr_accessor :name
    attr_accessor :description
    attr_accessor :all_licensed_modules
    attr_accessor :all_global_engines
    attr_accessor :all_global_report_templates
    attr_accessor :all_global_scan_templates
    attr_accessor :global_report_templates
    attr_accessor :global_scan_engines
    attr_accessor :global_scan_templates
    attr_accessor :licensed_modules
    attr_accessor :restricted_report_formats
    attr_accessor :restricted_report_sections

    def self.load(connection, id)
      xml = '<SiloProfileConfigRequest session-id="' + connection.session_id + '"'
      xml << %( silo-profile-id="#{id}")
      xml << ' />'
      r = connection.execute(xml, '1.2')

      if r.success
        r.res.elements.each('SiloProfileConfigResponse/SiloProfileConfig') do |config|
          puts config
          return SiloProfile.parse(config)
        end
      end
      nil
    end

    def self.parse(xml)
      profile = new
      profile.id = xml.attributes['id']
      profile.name = xml.attributes['name']
      profile.description = xml.attributes['description']
      profile.all_licensed_modules = xml.attributes['all-licensed-modules']
      profile.all_global_engines = xml.attributes['all-global-engines']
      profile.all_global_report_templates = xml.attributes['all-global-report-templates']
      profile.all_global_scan_templates = xml.attributes['all-global-scan-templates']

      profile.global_report_templates = []
      xml.elements.each('GlobalReportTemplates/GlobalReportTemplate') {|template| profile.global_report_templates << template.attributes['name'] }

      profile.global_scan_engines = []
      xml.elements.each('GlobalScanEngines/GlobalScanEngine') {|engine| profile.global_scan_engines << engine.attributes['name'] }

      profile.global_scan_templates = []
      xml.elements.each('GlobalScanTemplates/GlobalScanTemplate') {|template| profile.global_scan_templates << template.attributes['name'] }

      profile.licensed_modules = []
      xml.elements.each('LicensedModules/LicensedModule') {|license_module| profile.licensed_modules << license_module.attributes['name'] }

      profile.restricted_report_formats = []
      xml.elements.each('RestrictedReportFormats/RestrictedReportFormat') {|format| profile.restricted_report_formats << format.attributes['name'] }

      profile.restricted_report_sections = []
      xml.elements.each('RestrictedReportSections/RestrictedReportSection') {|section| profile.restricted_report_sections << section.attributes['name'] }

      profile
    end

    # Updates this silo profile on a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this silo profile will be saved.
    # @return [String] Silo Profile ID assigned to this configuration, if successful.
    #
    def update(connection)
      r = connection.execute('<SiloProfileUpdateRequest session-id="' + connection.session_id + '">' + to_xml + ' </SiloProfileUpdateRequest>', '1.2')
      @id = r.attributes['silo-profile-id'] if r.success
    end

    # Saves this silo profile to a Nexpose console.
    #
    # @param [Connection] connection Connection to console where this silo profile will be saved.
    # @return [String] Silo Profile ID assigned to this configuration, if successful.
    #
    def create(connection)
      r = connection.execute('<SiloProfileCreateRequest session-id="' + connection.session_id + '">' + to_xml + ' </SiloProfileCreateRequest>', '1.2')
      @id = r.attributes['silo-profile-id'] if r.success
    end

    def as_xml
      xml = REXML::Element.new('SiloProfileConfig')
      xml.add_attributes({'id' => @id,
                          'name' => @name,
                          'description' => @description,
                          'all-licensed-modules' => @all_licensed_modules,
                          'all-global-engines' => @all_global_engines,
                          'all-global-report-templates' => @all_global_report_templates,
                          'all-global-scan-templates' => @all_global_scan_templates})

      unless @global_report_templates.empty?
        templates = xml.add_element('GlobalReportTemplates')
        @global_report_templates.each do |template|
          templates.add_element('GlobalReportTemplate', {'name' => template})
        end
      end

      unless @global_scan_engines.empty?
        engines = xml.add_element('GlobalScanEngines')
        @global_report_templates.each do |engine|
          engines.add_element('GlobalScanEngine', {'name' => engine})
        end
      end

      unless @global_scan_templates.empty?
        templates = xml.add_element('GlobalScanTemplates')
        @global_scan_templates.each do |template|
          templates.add_element('GlobalScanTemplate', {'name' => template})
        end
      end

      unless @licensed_modules.empty?
        licensed_modules = xml.add_element('LicensedModules')
        @licensed_modules.each do |licensed_module|
          licensed_modules.add_element('LicensedModule', {'name' => licensed_module})
        end
      end

      unless @restricted_report_formats.empty?
        formats = xml.add_element('RestrictedReportFormats')
        @restricted_report_formats.each do |format|
          formats.add_element('RestrictedReportFormat', {'name' => format})
        end
      end

      unless @restricted_report_sections.empty?
        sections = xml.add_element('RestrictedReportSections')
        @restricted_report_sections.each do |section|
          sections.add_element('RestrictedReportSection', {'name' => section})
        end
      end

      xml
    end

    def to_xml
      as_xml.to_s
    end
  end

  class SiloProfileSummary
    attr_accessor :id
    attr_accessor :name
    attr_accessor :description
    attr_accessor :global_report_template_count
    attr_accessor :global_scan_engine_count
    attr_accessor :global_scan_template_count
    attr_accessor :licensed_module_count
    attr_accessor :restricted_report_section_count
    attr_accessor :all_licensed_modules
    attr_accessor :all_global_engines
    attr_accessor :all_global_report_templates
    attr_accessor :all_global_scan_templates

    def self.parse(xml)
      profile = new
      profile.id = xml.attributes['id']
      profile.name = xml.attributes['name']
      profile.description = xml.attributes['description']
      profile.global_report_template_count = xml.attributes['global-report-template-count']
      profile.global_scan_engine_count = xml.attributes['global-scan-engine-count']
      profile.global_scan_template_count = xml.attributes['global-scan-template-count']
      profile.licensed_module_count = xml.attributes['licensed-module-count']
      profile.restricted_report_section_count = xml.attributes['restricted-report-section-count']
      profile.all_licensed_modules = xml.attributes['all-licensed-modules']
      profile.all_global_engines = xml.attributes['all-global-engines']
      profile.all_global_report_templates = xml.attributes['all-global-report-templates']
      profile.all_global_scan_templates = xml.attributes['all-global-scan-templates']
      profile
    end
  end
end