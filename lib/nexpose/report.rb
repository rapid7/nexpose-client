module Nexpose
  module NexposeAPI
    include XMLUtils

    # Generate a new report using the specified report definition.
    def report_generate(report_id, wait = false)
      xml = make_xml('ReportGenerateRequest', {'report-id' => report_id})
      response = execute(xml)
      summary = nil
      if response.success
        response.res.elements.each('//ReportSummary') do |summary|
          summary = ReportSummary.parse(summary)
          # If not waiting or the report is finished, return now.
          return summary unless wait and summary.status == 'Started'
        end
      end
      so_far = 0
      while wait
        summary = report_last(report_id)
        return summary unless summary.status == 'Started'
        sleep 5
        so_far += 5
        if so_far % 60 == 0
          puts "Still waiting. Current status: #{summary.status}"
        end
      end
      nil
    end

    # Provide a history of all reports generated with the specified report
    # definition.
    def report_history(report_config_id)
      xml = make_xml('ReportHistoryRequest', {'reportcfg-id' => report_config_id})
      ReportSummary.parse_all(execute(xml))
    end

    # Get the details of the last report generated with the specified report id.
    def report_last(report_config_id)
      history = report_history(report_config_id)
      history.sort { |a, b| b.generated_on <=> a.generated_on }.first
    end

    # Delete a previously generated report definition.
    # Also deletes any reports generated from that configuration.
    def report_config_delete(report_config_id)
      xml = make_xml('ReportDeleteRequest', {'reportcfg-id' => report_config_id})
      execute(xml).success
    end

    # Delete a previously generated report.
    def report_delete(report_id)
      xml = make_xml('ReportDeleteRequest', {'report-id' => report_id})
      execute(xml).success
    end

    # Provide a list of all report templates the user can access on the
    # Security Console.
    def report_template_listing
      r = execute(make_xml('ReportTemplateListingRequest', {}))
      templates = []
      if (r.success)
        r.res.elements.each('//ReportTemplateSummary') do |template|
          templates << ReportTemplateSummary.parse(template)
        end
      end
      templates
    end

    # Retrieve the configuration for a report template.
    def get_report_template(template_id)
      xml = make_xml('ReportTemplateConfigRequest', {'template-id' => template_id})
      ReportTemplate.parse(execute(xml))
    end

    # Provide a listing of all report definitions the user can access on the
    # Security Console.
    def report_listing
      r = execute(make_xml('ReportListingRequest', {}))
      reports = []
      if (r.success)
        r.res.elements.each('//ReportConfigSummary') do |report|
          reports << ReportConfigSummary.parse(report)
        end
      end
      reports
    end

    # Retrieve the configuration for a report definition.
    def get_report_config(report_config_id)
      xml = make_xml('ReportConfigRequest', {'reportcfg-id' => report_config_id})
      ReportConfig.parse(execute(xml))
    end
  end

  # Data object for report configuration information.
  # Not meant for use in creating new configurations.
  class ReportConfigSummary
    # The report definition (config) ID.
    attr_reader :config_id
    # The ID of the report template.
    attr_reader :template_id
    # The current status of the report.
    # One of: Started|Generated|Failed|Aborted|Unknown
    attr_reader :status
    # The date and time the report was generated, in ISO 8601 format.
    attr_reader :generated_on
    # The URL to use to access the report (not set for database exports).
    attr_reader :report_uri
    # The visibility (scope) of the report definition.
    # One of: (global|silo).
    attr_reader :scope

    def initialize(config_id, template_id, status, generated_on, report_uri, scope)
      @config_id = config_id
      @template_id = template_id
      @status = status 
      @generated_on = generated_on 
      @report_uri = report_uri 
      @scope = scope 
    end

    def self.parse(xml)
      ReportConfigSummary.new(xml.attributes['cfg-id'],
                              xml.attributes['template-id'],
                              xml.attributes['status'],
                              xml.attributes['generated-on'],
                              xml.attributes['report-URI'],
                              xml.attributes['scope'])
    end
  end

  # Summary of a single report.
  class ReportSummary
    # The id of the generated report.
    attr_reader :id
    # The report definition (configuration) ID.
    attr_reader :cfg_id
    # The current status of the report.
    # One of: Started|Generated|Failed|Aborted|Unknown
    attr_reader :status
    # The date and time the report was generated, in ISO 8601 format.
    attr_reader :generated_on
    # The relative URI to use to access the report.
    attr_reader :report_uri

    def initialize(id, cfg_id, status, generated_on, report_uri)
      @id = id
      @cfg_id = cfg_id
      @status = status
      @generated_on = generated_on
      @report_uri = report_uri
    end

    # Delete this report.
    def delete(connection)
      connection.report_delete(@id)
    end

    def self.parse(xml)
      ReportSummary.new(xml.attributes['id'], xml.attributes['cfg-id'], xml.attributes['status'], xml.attributes['generated-on'], xml.attributes['report-URI'])
    end

    def self.parse_all(response)
      summaries = []
      if (response.success)
        response.res.elements.each('//ReportSummary') do |summary|
          summaries << ReportSummary.parse(summary)
        end
      end
      summaries
    end
  end

  # Definition object for an adhoc report configuration.
  #
  # NOTE: Only text, pdf, and csv currently work reliably.
  class AdhocReportConfig
    # The ID of the report template used.
    attr_accessor :template_id
    # Format. One of: pdf|html|rtf|xml|text|csv|db|raw-xml|raw-xml-v2|ns-xml|qualys-xml
    attr_accessor :format

    # Array of filters associated with this report.
    attr_accessor :filters
    # Baseline comparison highlights the changes between two scans, including
    # newly discovered assets, services and vulnerabilities, assets and services
    # that are no longer available and vulnerabilities that were mitigated or
    # fixed. The current scan results can be compared against the results of the
    # first scan, the most recent (previous) scan, or the scan results from a
    # particular date.
    attr_accessor :baseline

    def initialize(template_id, format, site_id = nil)
      @template_id = template_id 
      @format = format 

      @filters = []
      @filters << Filter.new('site', site_id) if site_id
    end

    # Add a new filter to this report configuration.
    def add_filter(type, id)
      filters << Filter.new(type, id)
    end

    def to_xml
      xml = %Q{<AdhocReportConfig format='#{@format}' template-id='#{@template_id}'>}

      xml << '<Filters>'
      @filters.each { |filter| xml << filter.to_xml }
      xml << '</Filters>'

      xml << %Q{<Baseline compareTo='#{@baseline}' />} if @baseline

      xml << '</AdhocReportConfig>'
    end

    include XMLUtils

    # Generate a report once using a simple configuration, and send it back
    # in a multi-part mime response.
    def generate(connection)
      xml = %Q{<ReportAdhocGenerateRequest session-id='#{connection.session_id}'>}
      xml << to_xml
      xml << '</ReportAdhocGenerateRequest>'
      response = connection.execute(xml)
      if response.success
        content_type_response = response.raw_response.header['Content-Type']
        if content_type_response =~ /multipart\/mixed;\s*boundary=([^\s]+)/
          # Nexpose sends an incorrect boundary format which breaks parsing
          # e.g., boundary=XXX; charset=XXX
          # Fix by removing everything from the last semi-colon onward.
          last_semi_colon_index = content_type_response.index(/;/, content_type_response.index(/boundary/))
          content_type_response = content_type_response[0, last_semi_colon_index]

          data = 'Content-Type: ' + content_type_response + "\r\n\r\n" + response.raw_response_data
          doc = Rex::MIME::Message.new(data)
          doc.parts.each do |part|
            if /.*base64.*/ =~ part.header.to_s
              if (@format == 'text') or (@format == 'pdf') or (@format == 'csv')
                return part.content.unpack('m*')[0]
              else
                # FIXME This isn't working.
                return parse_xml(part.content.unpack("m*")[0])
              end
            end
          end
        end
      end
    end
  end

  # Definition object for a report configuration.
  class ReportConfig < AdhocReportConfig
    # The ID of the report definition (config).
    # Use -1 to create a new definition.
    attr_accessor :id
    # The unique name assigned to the report definition.
    attr_accessor :name
    attr_accessor :owner
    attr_accessor :timezone

    # Description associated with this report.
    attr_accessor :description
    # Array of user IDs which have access to resulting reports.
    attr_accessor :users
    # Configuration of when a report is generated.
    attr_accessor :generate
    # Report delivery configuration.
    attr_accessor :delivery
    # Database export configuration.
    attr_accessor :db_export

    # Construct a basic ReportConfig object.
    def initialize(name, template_id, format, id = -1, owner = nil, timezone = nil)
      @name = name
      @template_id = template_id
      @format = format
      @id = id
      @owner = owner
      @timezone = timezone

      @filters = []
      @users = []
    end

    # Retrieve the configuration for an existing report definition.
    def self.get(connection, report_config_id)
      connection.get_report_config(report_config_id)
    end

    # Build and save a report configuration against the specified site using
    # the supplied type and format.
    #
    # Returns the new configuration.
    def self.build(connection, site_id, site_name, type, format, generate_now = false)
      name = %Q{#{site_name} #{type} report in #{format}}
      config = ReportConfig.new(name, type, format)
      config.generate = Generate.new(true, false)
      config.filters << Filter.new('site', site_id)
      config.save(connection, generate_now)
      config
    end

    # Save the configuration of this report definition.
    def save(connection, generate_now = false)
      xml = %Q{<ReportSaveRequest session-id='#{connection.session_id}' generate-now='#{generate_now ? 1 : 0}'>}
      xml << to_xml
      xml << '</ReportSaveRequest>'
      response = connection.execute(xml)
      if response.success
        @id = response.attributes['reportcfg-id']
      end
    end

    # Generate a new report using this report definition.
    def generate(connection, wait = false)
      connection.report_generate(@id, wait)
    end

    # Delete this report definition from the Security Console.
    # Deletion will also remove all reports previously generated from the
    # configuration.
    def delete(connection)
      connection.report_config_delete(@id)
    end

    def to_xml
      xml = %Q{<ReportConfig format='#{@format}' id='#{@id}' name='#{@name}' owner='#{@owner}' template-id='#{@template_id}' timezone='#{@timezone}'>}
      xml << %Q{<description>#{@description}</description>} if @description

      xml << '<Filters>'
      @filters.each { |filter| xml << filter.to_xml }
      xml << '</Filters>'

      xml << '<Users>'
      @users.each { |user| xml << %Q{<user id='#{user}' />} }
      xml << '</Users>'

      xml << %Q{<Baseline compareTo='#{@baseline}' />} if @baseline
      xml << @generate.to_xml if @generate
      xml << @delivery.to_xml if @delivery
      xml << @db_export.to_xml if @db_export

      xml << '</ReportConfig>'
    end

    def self.parse(xml)
      xml.res.elements.each('//ReportConfig') do |cfg|
        config = ReportConfig.new(cfg.attributes['name'],
                                  cfg.attributes['template-id'],
                                  cfg.attributes['format'],
                                  cfg.attributes['id'],
                                  cfg.attributes['owner'],
                                  cfg.attributes['timezone'])

        cfg.elements.each('//description') do |desc|
          config.description = desc.text
        end

        config.filters = Filter.parse(xml)

        cfg.elements.each('//user') do |user|
          config.users << user.attributes['id'].to_i
        end

        cfg.elements.each('//Baseline') do |baseline|
          config.baseline = baseline.attributes['compareTo']
        end

        config.generate = Generate.parse(cfg)
        config.delivery = Delivery.parse(cfg)
        config.db_export = DBExport.parse(cfg)

        return config
      end
      nil
    end
  end

  # Object that represents a report filter which determines which sites, asset
  # groups, and/or devices that a report is run against.
  # 
  # The configuration must include at least one of device (asset), site,
  # group (asset group) or scan filter to define the scope of report.
  # The vuln-status filter can be used only with raw report formats: csv
  # or raw_xml. If the vuln-status filter is not included in the configuration,
  # all the vulnerability test results (including invulnerable instances) are
  # exported by default in csv and raw_xml reports.
  class Filter
    # The ID of the specific site, group, device, or scan.
    # For scan, this can also be "last" for the most recently run scan.
    # For vuln-status, the ID can have one of the following values:
    # 1. vulnerable-exploited (The check was positive. An exploit verified the vulnerability.)
    # 2. vulnerable-version (The check was positive. The version of the scanned service or software is associated with known vulnerabilities.)
    # 3. potential (The check for a potential vulnerability was positive.)
    # These values are supported for CSV and XML formats.
    attr_reader :id
    # One of: site|group|device|scan|vuln-categories|vuln-severity|vuln-status|cyberscope-component|cyberscope-bureau|cyberscope-enclave
    attr_reader :type

    def initialize(type, id)
      @type = type
      @id = id
    end

    def to_xml
      %Q{<filter id='#{@id}' type='#{@type}' />}
    end

    def self.parse(xml)
      filters = []
      xml.res.elements.each('//Filters/filter') do |filter|
        filters << Filter.new(filter.attributes['type'], filter.attributes['id']) 
      end
      filters
    end
  end

  # Data object associated with when a report is generated.
  class Generate
    # Will the report be generated after a scan completes (1),
    # or is it ad-hoc/scheduled (0).
    attr_accessor :after_scan
    # Whether or not a scan is scheduled (0|1).
    attr_accessor :scheduled
    # Schedule associated with the report.
    attr_accessor :schedule

    def initialize(after_scan, scheduled, schedule = nil)
      @after_scan = after_scan
      @scheduled = scheduled
      @schedule = schedule
    end

    def to_xml
      xml = %Q{<Generate after-scan='#{@after_scan ? 1 : 0}' schedule='#{@scheduled ? 1 : 0}'>}
      xml << @schedule.to_xml if @schedule
      xml << '</Generate>'
    end

    def self.parse(xml)
      xml.elements.each('//Generate') do |generate|
        if generate.attributes['after-scan'] == '1'
          return Generate.new(true, false)
        else
          if generate.attributes['schedule'] == '1'
            schedule = Schedule.parse(xml)
            return Generate.new(false, true, schedule)
          end
          return Generate.new(false, false)
        end
      end
      nil
    end
  end

  # Data object for configuration of where a report is stored or delivered.
  class Delivery
    # Whether to store report on server.
    attr_accessor :store_on_server
    # Directory location to store report in (for non-default storage).
    attr_accessor :location
    # E-mail configuration.
    attr_accessor :email

    def initialize(store_on_server, location = nil, email = nil)
      @store_on_server = store_on_server
      @location = location
      @email = email
    end

    def to_xml
      xml = '<Delivery>'
      xml << %Q{<Storage storeOnServer='#{@store_on_server ? 1 : 0}'>}
      xml << %Q{<location>#{@location}</location>} if @location
      xml << '</Storage>'
      xml << @email.to_xml if @email
      xml << '</Delivery>'
    end

    def self.parse(xml)
      xml.elements.each('//Delivery') do |delivery|
        on_server = false
        location = nil
        xml.elements.each('//Storage') do |storage|
          on_server = true if storage.attributes['storeOnServer'] == '1'
          xml.elements.each('//location') do |loc|
            location = loc.text
          end
        end

        email = Email.parse(xml)

        return Delivery.new(on_server, location, email)
      end
      nil
    end
  end

  # Configuration structure for database exporting of reports.
  class DBExport
    # The DB type to export to.
    attr_accessor :type
    # Credentials needed to export to the specified database.
    attr_accessor :credentials
    # Map of parameters for this DB export configuration.
    attr_accessor :parameters

    def initialize(type)
      @type = type
      @parameters = {}
    end

    def to_xml
      xml = %Q{<DBExport type='#{@type}'>}
      xml << @credentials.to_xml if @credentials
      @parameters.each_pair do |name, value|
        xml << %Q{<param name='#{name}'>#{value}</param>}
      end
      xml << '</DBExport>'
    end

    def self.parse(xml)
      xml.elements.each('//DBExport') do |dbexport|
        config = DBExport.new(dbexport.attributes['type'])
        config.credentials = ExportCredential.parse(xml) 
        xml.elements.each('//param') do |param|
          config.parameters[param.attributes['name']] = param.text
        end
        return config
      end
      nil
    end
  end

  # DBExport credentials configuration object.
  #
  # The userid, password and realm attributes should ONLY be used
  # if a security blob cannot be generated and the data is being
  # transmitted/stored using external encryption (e.g., HTTPS).
  class ExportCredential
    # Security blob for exporting to a database.
    attr_accessor :credential
    attr_accessor :userid
    attr_accessor :password
    # DB specific, usually the database name.
    attr_accessor :realm

    def initialize(credential)
      @credential = credential
    end

    def to_xml
      xml = '<credentials'
      xml << %Q{ userid='#{@userid}'} if @userid
      xml << %Q{ password='#{@password}'} if @password
      xml << %Q{ realm='#{@realm}'} if @realm
      xml << '>'
      xml << @credential if @credential
      xml << '</credentials>'
    end

    def self.parse(xml)
      xml.elements.each('//credentials') do |creds|
        credential = ExportCredential.new(creds.text)
        # The following attributes may not exist.
        credential.userid = creds.attributes['userid']
        credential.password = creds.attributes['password']
        credential.realm = creds.attributes['realm']
        return credential
      end
      nil
    end
  end

  # Data object for report template summary information.
  # Not meant for use in creating new templates.
  class ReportTemplateSummary
    # The ID of the report template.
    attr_reader :id
    # The name of the report template.
    attr_reader :name
    # One of: data|document. With a data template, you can export
    # comma-separated value (CSV) files with vulnerability-based data.
    # With a document template, you can create PDF, RTF, HTML, or XML reports
    # with asset-based information.
    attr_reader :type
    # The visibility (scope) of the report template. One of: global|silo
    attr_reader :scope
    # Whether the report template is built-in, and therefore cannot be modified.
    attr_reader :built_in
    # Description of the report template.
    attr_reader :description

    def initialize(id, name, type, scope, built_in, description)
      @id = id
      @name = name
      @type = type
      @scope = scope
      @built_in = built_in
      @description = description
    end

    def self.parse(xml)
      description = nil
      xml.elements.each('description') { |desc| description = desc.text }
      ReportTemplateSummary.new(xml.attributes['id'],
                                xml.attributes['name'],
                                xml.attributes['type'],
                                xml.attributes['scope'],
                                xml.attributes['builtin'] == '1',
                                description)
    end
  end

  # Definition object for a report template.
  class ReportTemplate
    # The ID of the report template.
    attr_accessor :id
    # The name of the report template.
    attr_accessor :name
    # With a data template, you can export comma-separated value (CSV) files
    # with vulnerability-based data. With a document template, you can create
    # PDF, RTF, HTML, or XML reports with asset-based information. When you
    # retrieve a report template, the type will always be visible even though
    # type is implied. When ReportTemplate is sent as a request, and the type
    # attribute is not provided, the type attribute defaults to document,
    # allowing for backward compatibility with existing API clients.
    attr_accessor :type
    # The visibility (scope) of the report template.
    # One of: global|silo
    attr_accessor :scope
    # The report template is built-in, and cannot be modified.
    attr_accessor :built_in
    # Description of this report template.
    attr_accessor :description

    # Array of report sections.
    attr_accessor :sections
    # Map of report properties.
    attr_accessor :properties
    # Display asset names with IPs.
    attr_accessor :show_device_names

    def initialize(name, type = 'document', id = -1, scope = 'silo', built_in = false)
      @name = name
      @type = type
      @id = id
      @scope = scope
      @built_in = built_in

      @sections = []
      @properties = {}
      @show_device_names = false
    end

    # Save the configuration for a report template.
    def save(connection)
      xml = %Q{<ReportTemplateSaveRequest session-id='#{connection.session_id}' scope='#{@scope}'>}
      xml << to_xml
      xml << '</ReportTemplateSaveRequest>'
      response = connection.execute(xml)
      if response.success
        @id = response.attributes['template-id']
      end
    end

    def delete(connection)
      xml = %Q{<ReportTemplateDeleteRequest session-id='#{connection.session_id}' template-id='#{@id}'>}
      xml << '</ReportTemplateDeleteRequest>'
      response = connection.execute(xml)
      if response.success
        @id = response.attributes['template-id']
      end
    end

    # Retrieve the configuration for a report template.
    def self.get(connection, template_id)
      connection.get_report_template(template_id)
    end

    include Sanitize

    def to_xml
      xml = %Q{<ReportTemplate id='#{@id}' name='#{@name}' type='#{@type}'}
      xml << %Q{ scope='#{@scope}'} if @scope
      xml << %Q{ builtin='#{@built_in}'} if @built_in
      xml << '>'
      xml << %Q{<description>#{@description}</description>} if @description

      xml << '<ReportSections>'
      properties.each_pair do |name, value|
        xml << %Q{<property name='#{name}'>#{replace_entities(value)}</property>}
      end
      @sections.each { |section| xml << section.to_xml }
      xml << '</ReportSections>'

      xml << %Q{<Settings><showDeviceNames enabled='#{@show_device_names ? 1 : 0}' /></Settings>}
      xml << '</ReportTemplate>'
    end

    def self.parse(xml)
      xml.res.elements.each('//ReportTemplate') do |tmp|
        template = ReportTemplate.new(tmp.attributes['name'],
                                      tmp.attributes['type'],
                                      tmp.attributes['id'],
                                      tmp.attributes['scope'] || 'silo',
                                      tmp.attributes['builtin'])
        tmp.elements.each('//description') do |desc|
          template.description = desc.text
        end

        tmp.elements.each('//ReportSections/property') do |property|
          template.properties[property.attributes['name']] = property.text
        end

        tmp.elements.each('//ReportSection') do |section|
          template.sections << Section.parse(section)
        end

        tmp.elements.each('//showDeviceNames') do |show|
          template.show_device_names = show.attributes['enabled'] == '1'
        end

        return template
      end
      nil
    end
  end

  # Section specific content to include in a report template.
  class Section
    # Name of the report section.
    attr_accessor :name
    # Map of properties specific to the report section.
    attr_accessor :properties

    def initialize(name)
      @name = name
      @properties = {}
    end

    include Sanitize

    def to_xml
      xml = %Q{<ReportSection name='#{@name}'>}
      properties.each_pair do |name, value|
        xml << %Q{<property name='#{name}'>#{replace_entities(value)}</property>}
      end
      xml << '</ReportSection>'
    end

    def self.parse(xml)
      name = xml.attributes['name']
      xml.elements.each("//ReportSection[@name='#{name}']") do |elem|
        section = Section.new(name)
        elem.elements.each("//ReportSection[@name='#{name}']/property") do |property|
          section.properties[property.attributes['name']] = property.text
        end
        return section
      end
      nil
    end
  end
end
