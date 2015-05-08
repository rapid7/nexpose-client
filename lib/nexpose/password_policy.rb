module Nexpose
  require 'json'
  # Configuration structure for password policies.
  class Password_policy < APIObject
    # Policy name
    attr_accessor :policy_name
    # Default min length = 6.
    attr_accessor :min_length
    # Max length of password can reach upto 32 characters.
    attr_accessor :max_length
    # Between 0-4 capital letters can be included in a password
    attr_accessor :capitals
    # Between 0-4 digits can be included in a password
    attr_accessor :digits
    # Between 0-4 special characters can be included in a password
    attr_accessor :special_chars
    # Between 30-120 days can be set for expiry time
    attr_accessor :expiry_days

    def initialize(name, minlength, maxlength, specialchars, capitals, digits, expirydays)
      @policy_name = name.to_s
      @min_length = minlength.to_i
      @max_length = maxlength.to_i
      @special_chars = specialchars.to_i
      @capitals = capitals.to_i
      @digits =  digits.to_i
      @expiry_days = expirydays.to_i
    end

    def self.from_hash(hash)
      password_policy = new(hash[:policy_name], hash[:min_length], hash[:max_length],  hash[:special_chars],  hash[:capitals], hash[:digits], hash[:expiry_days])
      password_policy
    end

    def to_h
      password_hash = {
          policy_name: @policy_name,
          min_length: @min_length,
          max_length: @max_length,
          special_chars: @special_chars,
          capitals: @capitals,
          digits: @digits,
          expiry_days: @expiry_days
      }
      password_hash
    end

    def to_json
      JSON.generate(to_h)
    end

    def save(nsc)
      params = to_json
      AJAX.post(nsc, '/api/2.1/password_policy/', params, AJAX::CONTENT_TYPE::JSON)
    end

    def self.json_initializer(data)
      new(data[:policy_name], data[:min_length], data[:max_length],  data[:special_chars],  data[:capitals], data[:digits], data[:expiry_days])
    end

    def self.load(nsc)
      uri = '/api/2.1/password_policy/'
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true)
      password_policy = self.json_initializer(hash)
      password_policy
    end
  end
end