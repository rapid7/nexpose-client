module Nexpose

  # Contains the shared methods for the SiteCredential and SharedCredential Objects.
  # See Nexpose::SiteCredential or Nexpose::SharedCredential for additional info.
  class Credential

    DEFAULT_PORTS = { 'cvs' => 2401,
                  'ftp' => 21,
                  'http' => 80,
                  'as400' => 449,
                  'notes' => 1352,
                  'tds' => 1433,
                  'sybase' => 5000,
                  'cifs' => 445,
                  'cifshash' => 445,
                  'oracle' => 1521,
                  'pop' => 110,
                  'postgresql' => 5432,
                  'remote execution' => 512,
                  'snmp' => 161,
                  'snmpv3' => 161,
                  'ssh' => 22,
                  'ssh-key' => 22,
                  'telnet' => 23,
                  'mysql' => 3306,
                  'db2' => 50000 }


    # Credential type options.
    module Type
      # Concurrent Versioning System (CVS)
      CVS = 'cvs'
      # File Transfer Protocol (FTP)
      FTP = 'ftp'
      # Web Site HTTP Authentication
      HTTP = 'http'
      # IBM AS/400
      AS400 = 'as400'
      # Lotus Notes/Domino
      NOTES = 'notes'
      # Microsoft SQL Server
      TDS = 'tds'
      # Sybase SQL Server
      SYBASE = 'sybase'
      # Microsoft Windows/Samba (SMB/CIFS)
      CIFS = 'cifs'
      # Microsoft Windows/Samba LM/NTLM Hash (SMB/CIFS)
      CIFSHASH = 'cifshash'
      # Oracle
      ORACLE = 'oracle'
      # Post Office Protocol (POP)
      POP = 'pop'
      # PostgreSQL
      POSTGRESQL = 'postgresql'
      # Remote Execution
      REMOTE_EXECUTION = 'remote execution'
      # Simple Network Management Protocol
      SNMP = 'snmp'
      # Simple Network Management Protocol v3
      SNMPV3 = 'snmpv3'
      # Secure Shell (SSH)
      SSH = 'ssh'
      # Secure Shell (SSH) Public Key
      SSH_KEY = 'ssh-key'
      # TELNET
      TELNET = 'telnet'
      # MySQL Server
      MYSQL = 'mysql'
      # DB2
      DB2 = 'db2'
    end


    # Permission Elevation Types
    module ElevationType
      NONE = 'NONE'
      SUDO = 'SUDO'
      SUDOSU = 'SUDOSU'
      SU = 'SU'
    end


    # Test this credential against a target where the credentials should apply.
    # Only works for a newly created credential. Loading an existing credential
    # will likely fail.
    #
    # @param [Connection] nsc An active connection to the security console.
    # @param [String] target Target host to check credentials against.
    # @param [Fixnum] engine_id ID of the engine to use for testing credentials.
    #   Will default to the local engine if none is provided.
    #
    def test(nsc, target, engine_id = nil)
      unless engine_id
        local_engine = nsc.engines.find { |e| e.name == 'Local scan engine' }
        engine_id = local_engine.id
      end

      parameters = _to_param(target, engine_id)
      ## fix @port
      ## _to_param hash it out.
      xml = AJAX.form_post(nsc, '/ajax/test_admin_credentials.txml', parameters)
      result = REXML::XPath.first(REXML::Document.new(xml), 'TestAdminCredentialsResult')
      result.attributes['success'].to_i == 1
    end


    def _to_param(target, engine_id)
      port = @port
      port = Credential::DEFAULT_PORTS[@type] if port.nil?

      { engineid: engine_id,
        sc_creds_dev: target,
        sc_creds_svc: @type,
        sc_creds_database: @database,
        sc_creds_domain: @domain,
        sc_creds_uname: @username,
        sc_creds_password: @password,
        sc_creds_pemkey: @pem_key,
        sc_creds_port: port,
        sc_creds_privilegeelevationusername: @privilege_username,
        sc_creds_privilegeelevationpassword: @privilege_password,
        sc_creds_privilegeelevationtype: @privilege_type,
        sc_creds_snmpv3authtype: @auth_type,
        sc_creds_snmpv3privtype: @privacy_type,
        sc_creds_snmpv3privpassword: @privacy_password,
        siteid: -1 }
    end

  end


end
