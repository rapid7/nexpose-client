module Nexpose

  # Contains the shared methods for the SiteCredential and SharedCredential Objects.
  # See Nexpose::SiteCredential or Nexpose::SharedCredential for additional info.
  class Credential < APIObject

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


    # Credential scope
    module Scope
      ALL_SITES_ENABLED_DEFAULT = 'A'
      ALL_SITES_DISABLED_DEFAULT = 'G'
      SITE_SPECIFIC = 'S'
    end

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

    #Authentication type for SNMP version 3
    module AuthenticationType
      NOAUTH = 'noauth'   # No authentication protocol
      SHA = 'sha'         # SHA authentication protocol
      MD5 = 'md5'         # MD5 authentication protocol
    end

    # PrivacyType for snmp version 3
    module PrivacyType
      NOPRIV = 'nopriv'                                               # No privacy protocol
      DES = 'des'                                                     # DES privacy protocol
      AES128 = 'aes128'                                               # AES128 privacy protocol
      AES192 = 'aes192'                                               # AES192 privacy protocol
      AES192WITH3DESKEYEXTENSION = 'aes192with3deskeyextension'       # AES192 with 3 DES key extension privacy protocol
      AES256 = 'aes256'                                               # AES256 privacy protocol
      AES265WITH3DESKEYEXTENSION = 'aes265with3deskeyextension'       # AES256 with 3 DES key extension privacy protocol
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
      xml = AJAX.form_post(nsc, '/data/credential/shared/test', parameters)
      result = REXML::XPath.first(REXML::Document.new(xml), 'TestAdminCredentialsResult')
      result.attributes['success'].to_i == 1
    end


    def _to_param(target, engine_id, port, siteid)
      { engineid: engine_id,
        sc_creds_dev: target,
        sc_creds_svc: @service,
        sc_creds_database: @database,
        sc_creds_domain: @domain,
        sc_creds_uname: @user_name,
        sc_creds_password: @password,
        sc_creds_pemkey: @pem_format_private_key,
        sc_creds_port: port,
        sc_creds_privilegeelevationusername: @permission_elevation_user,
        sc_creds_privilegeelevationpassword: @permission_elevation_password,
        sc_creds_privilegeelevationtype: @permission_elevation_type,
        sc_creds_snmpv3authtype: @authentication_type,
        sc_creds_snmpv3privtype: @privacy_type,
        sc_creds_snmpv3privpassword: @privacy_password,
        siteid: siteid }
    end

    # sets the Concurrent Versioning System (CVS) service
    def set_cvs_service(username = nil, password = nil)
      @user_name = username
      @password = password
      @service = Service::CVS
    end

    # sets the DB2 service
    def set_db2_service(database = nil, username = nil, password = nil)
      @database = database
      @user_name = username
      @password = password
      @service = Service::DB2
    end

    # sets the File Transfer Protocol (FTP) service
    def set_ftp_service(username = nil, password = nil)
      @user_name = username
      @password = password
      @service = Service::FTP
    end

    # sets the IBM AS/400 service.
    def set_as400_service(domain = nil, username = nil, password = nil)
      @domain = domain
      @user_name = username
      @password = password
      @service = Service::AS400
    end

    # sets the Lotus Notes/Domino service.
    def set_notes_service(password = nil)
      @notes_id_password = password
      @service = Service::NOTES
    end

    # sets the Microsoft SQL Server service.
    def set_tds_service(database = nil, domain = nil, username = nil, password = nil)
      @database = database
      @domain = domain
      @use_windows_auth = domain.nil?
      @user_name = username
      @password = password
      @service = Service::TDS
    end

    # sets the Microsoft Windows/Samba (SMB/CIFS) service.
    def set_cifs_service(domain = nil, username = nil, password = nil)
      @domain = domain
      @user_name = username
      @password = password
      @service = Service::CIFS
    end

    # sets the Microsoft Windows/Samba LM/NTLM Hash (SMB/CIFS) service.
    def set_cifshash_service(domain = nil, username = nil, password = nil)
      @domain = domain
      @user_name = username
      @password = password
      @service = Service::CIFSHASH
    end

    # sets the MySQL Server service.
    def set_mysql_service(database = nil, username = nil, password = nil)
      @database = database
      @user_name = username
      @password = password
      @service = Service::MYSQL
    end

    # sets the Oracle service.
    def set_oracle_service(sid = nil, username = nil, password = nil)
      @database = sid
      @user_name = username
      @password = password
      @service = Service::ORACLE
    end

    # sets the Post Office Protocol (POP) service.
    def set_pop_service(username = nil, password = nil)
      @user_name = username
      @password = password
      @service = Service::POP
    end

    # sets the PostgreSQL service.
    def set_postgresql_service(database = nil, username = nil, password = nil)
      @database = database
      @user_name = username
      @password = password
      @service = Service::POSTGRESQL
    end

    # sets the Remote Execution service.
    def set_remote_execution_service(username = nil, password = nil)
      @user_name = username
      @password = password
      @service = Service::REMOTE_EXECUTION
    end

    # sets the Secure Shell (SSH) service.
    def set_ssh_service(username = nil, password = nil, elevation_type = nil, elevation_user = nil, elevation_password = nil)
      @user_name = username
      @password = password
      @permission_elevation_type = elevation_type || ElevationType::NONE
      @permission_elevation_user = elevation_user
      @permission_elevation_password = elevation_password
      @service = Service::SSH
    end

    # sets the Secure Shell (SSH) Public Key service.
    def set_ssh_key_service(username, pemkey,  password = nil, elevation_type = nil, elevation_user = nil, elevation_password = nil)
      @user_name = username
      @password = password
      @pem_format_private_key = pemkey
      @permission_elevation_type = elevation_type || ElevationType::NONE
      @permission_elevation_user = elevation_user
      @permission_elevation_password = elevation_password
      @service = Service::SSH_KEY
    end

    # sets the Simple Network Management Protocol v1/v2c service.
    def set_snmp_service(community_name = nil)
      @community_name = community_name
      @service = Service::SNMP
    end

    # sets the Simple Network Management Protocol v3 service.
    def set_snmpv3_service(authentication_type = AuthenticationType::NOAUTH, username = nil, password = nil, privacy_type = PrivacyType::NOPRIV, privacy_password = nil)
      @authentication_type = authentication_type
      @user_name = username
      @password = password
      @privacy_type = privacy_type
      @privacy_password = privacy_password
      @service = Service::SNMPV3
    end

    # sets the Sybase SQL Server service.
    def set_sybase_service(database = nil, domain = nil, username = nil, password = nil)
      @database = database
      @domain = domain
      @use_windows_auth = domain.nil?
      @user_name = username
      @password = password
      @service = Service::SYBASE
    end

    # sets the Telnet service.
    def set_telnet_service(username = nil, password = nil)
      @user_name = username
      @password = password
      @service = Service::TELNET
    end

    # sets the Web Site HTTP Authentication service.
    def set_http_service(domain = nil, username = nil, password = nil)
      @domain = domain
      @user_name = username
      @password = password
      @service = Service::HTTP
    end
  end


end
