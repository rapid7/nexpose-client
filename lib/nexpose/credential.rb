module Nexpose

  # Contains the shared methods for the SiteCredential and SharedCredential Objects.
  # See Nexpose::SiteCredential or Nexpose::SharedCredential for additional info.
  class Credential

    # Mapping of Common Ports.
    DEFAULT_PORTS = { 'cvs'              => 2401,
                      'ftp'              => 21,
                      'http'             => 80,
                      'as400'            => 449,
                      'notes'            => 1352,
                      'tds'              => 1433,
                      'sybase'           => 5000,
                      'cifs'             => 445,
                      'cifshash'         => 445,
                      'oracle'           => 1521,
                      'pop'              => 110,
                      'postgresql'       => 5432,
                      'remote execution' => 512,
                      'snmp'             => 161,
                      'snmpv3'           => 161,
                      'ssh'              => 22,
                      'ssh-key'          => 22,
                      'telnet'           => 23,
                      'mysql'            => 3306,
                      'db2'              => 50000 }


    # Credential Service/Type Options.
    module Service
      CVS              = 'cvs'              # Concurrent Versioning System (CVS)
      FTP              = 'ftp'              # File Transfer Protocol (FTP)
      HTTP             = 'http'             # Web Site HTTP Authentication
      AS400            = 'as400'            # IBM AS/400
      NOTES            = 'notes'            # Lotus Notes/Domino
      TDS              = 'tds'              # Microsoft SQL Server
      SYBASE           = 'sybase'           # Sybase SQL Server
      CIFS             = 'cifs'             # Microsoft Windows/Samba (SMB/CIFS)
      CIFSHASH         = 'cifshash'         # Microsoft Windows/Samba LM/NTLM Hash (SMB/CIFS)
      ORACLE           = 'oracle'           # Oracle
      POP              = 'pop'              # Post Office Protocol (POP)
      POSTGRESQL       = 'postgresql'       # PostgreSQL
      REMOTE_EXECUTION = 'remote execution' # Remote Execution
      SNMP             = 'snmp'             # Simple Network Management Protocol
      SNMPV3           = 'snmpv3'           # Simple Network Management Protocol v3
      SSH              = 'ssh'              # Secure Shell (SSH)
      SSH_KEY          = 'ssh-key'          # Secure Shell (SSH) Public Key
      TELNET           = 'telnet'           # TELNET
      MYSQL            = 'mysql'            # MySQL Server
      DB2              = 'db2'              # DB2
    end


    # Permission Elevation / Privilege Escalation Types.
    module ElevationType
      NONE   = 'NONE'
      SUDO   = 'SUDO'
      SUDOSU = 'SUDOSU'
      SU     = 'SU'
      PBRUN  = 'PBRUN'
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
    def test(nsc, target, engine_id = nil, siteid = -1)
      unless engine_id
        engine_id = nsc.engines.find { |e| e.name == 'Local scan engine' }.id
      end
      @port = Credential::DEFAULT_PORTS[@service] if @port.nil?
      parameters = _to_param(target, engine_id, @port, siteid)
      xml = AJAX.form_post(nsc, '/ajax/test_admin_credentials.txml', parameters)
      result = REXML::XPath.first(REXML::Document.new(xml), 'TestAdminCredentialsResult')
      result.attributes['success'].to_i == 1
    end


    def _to_param(target, engine_id, port, siteid)
      { engineid: engine_id,
        sc_creds_dev: target,
        sc_creds_svc: @service,
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
        siteid: siteid }
    end

  end


end
