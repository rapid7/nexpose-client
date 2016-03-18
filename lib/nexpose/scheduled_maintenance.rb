module Nexpose
# Constants useful across the Nexpose module.
# Configuration structure for scheduled maintenance.
  class ScheduledMaintenance < APIObject
    require 'json'
    include JsonSerializer

    # Whether or not this maintenance schedule is enabled.
    attr_accessor :enabled
    # Valid schedule types: daily, hourly, monthly-date, monthly-day, weekly.
    attr_accessor :schedule_type
    # The repeat interval based upon type.
    attr_accessor :schedule_interval
    # The earliest date to generate the report on (in ISO 8601 format).
    attr_accessor :schedule_start
    # Whether the reindex task should run
    attr_accessor :reindex
    # Whether the compression task should run
    attr_accessor :compress
    # Whether the cleanup task should run
    attr_accessor :cleanup
    # Whether the maintenance should pause all local scans or wait for local scans to complete.
    attr_accessor :pause_local_scans

    def initialize(start, enabled=true, type, interval, reindex, compress, cleanup, pause_local_scans)
      @schedule_start = start
      @enabled = enabled
      @schedule_type = type
      @schedule_interval = interval.to_i
      @reindex = reindex
      @compress = compress
      @cleanup = cleanup
      @pause_local_scans = pause_local_scans
    end

    def to_json
      JSON.generate(to_h)
    end

    def save(nsc)
      params = to_json
      AJAX.post(nsc, '/api/2.1/schedule_maintenance/', params,  AJAX::CONTENT_TYPE::JSON)
    end

    def self.from_hash(hash)
      repeat_backup_hash = hash[:repeat_type]
      backup = new(hash[:start_date], hash[:enabled], repeat_backup_hash[:type], repeat_backup_hash[:interval], hash[:reindex], hash[:compression], hash[:cleanup], hash[:pause_local_scans])
      backup
    end

    def to_h
      maintenance_hash = {
          start_date: @schedule_start,
          enabled: @enabled,
          cleanup: @cleanup,
          reindex: @reindex,
          compression: @compress,
          pause_local_scans: @pause_local_scans
      }
      repeat_hash= {
          type: @schedule_type,
          interval: @schedule_interval
      }
      maintenance_hash[:repeat_type] = repeat_hash
      maintenance_hash
    end

    def self.load(nsc)
      uri = '/api/2.1/schedule_maintenance/'
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true).first
      Nexpose::ScheduledMaintenance.from_hash(hash || [])
    end

    def self.delete(nsc)
      AJAX.delete(nsc, '/api/2.1/schedule_maintenance/', AJAX::CONTENT_TYPE::JSON)
    end
  end
end