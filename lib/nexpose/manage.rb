# General management and diagnostic functions.
module Nexpose

  class Connection
    include XMLUtils

    # Execute an arbitrary console command that is supplied as text via the
    # supplied parameter. Console commands are documented in the
    # administrator's guide. If you use a command that is not listed in the
    # administrator's guide, the application will return the XMLResponse.
    #
    def console_command(cmd_string)
      xml = make_xml('ConsoleCommandRequest', {})
      cmd = REXML::Element.new('Command')
      cmd.text = cmd_string
      xml << cmd

      r = execute(xml)
      if r.success
        r.res.elements.each('//Output') do |out|
          return out.text.to_s
        end
      else
        false
      end
    end

    # Obtain system data, such as total RAM, free RAM, total disk space,
    # free disk space, CPU speed, number of CPU cores, and other vital
    # information.
    #
    def system_information
      r = execute(make_xml('SystemInformationRequest', {}))

      if r.success
        res = {}
        r.res.elements.each('//Statistic') do |stat|
          res[stat.attributes['name'].to_s] = stat.text.to_s
        end
        res
      else
        false
      end
    end

    # Obtain the version information for each scan engine.
    # Includes dates and ids for Product and Content versions.
    #
    def engine_versions
      JSON.parse(AJAX.post(self, '/data/engines'))['records']
    end

    # Induce the application to retrieve required updates and restart
    # if necessary.
    #
    def start_update
      execute(make_xml('StartUpdateRequest', {})).success
    end

    # Restart the application.
    #
    # There is no response to a RestartRequest. When the application
    # shuts down as part of the restart process, it terminates any active
    # connections. Therefore, the application cannot issue a response when it
    # restarts.
    #
    def restart
      execute(make_xml('RestartRequest', {})).success
    end

    # Output diagnostic information into log files, zip the files, and encrypt
    # the archive with a PGP public key that is provided as a parameter for the
    # API call. Then upload the archive using HTTPS to a URL that is specified
    # as an API parameter.
    #
    # @param uri Upload server to send the support log package to.
    #
    def send_log(uri = 'https://support.rapid7.com')
      url = REXML::Element.new('URL')
      url.text = uri
      tpt = REXML::Element.new('Transport')
      tpt.add_attribute('protocol', 'https')
      tpt << url
      xml = make_xml('SendLogRequest')
      xml << tpt

      execute(xml).success
    end
  end
end
