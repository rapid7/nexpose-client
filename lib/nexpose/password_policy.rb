module Nexpose
  require 'json'
  # Configuration structure for password policies.
  class PasswordPolicy < APIObject

    attr_accessor :policy_name
    attr_accessor :min_length
    attr_accessor :max_length
    attr_accessor :capitals
    attr_accessor :digits
    attr_accessor :special_chars


    def initialize(policy_name, minlength, maxlength, specialchars, capitals, digits)
      @policy_name = policy_name.to_s
      @min_length = minlength.to_i
      @max_length = maxlength.to_i
      @special_chars = specialchars.to_i
      @capitals = capitals.to_i
      @digits = digits.to_i
    end

    def self.from_hash(hash)
      new(hash[:policy_name],
          hash[:min_length],
          hash[:max_length],
          hash[:special_chars],
          hash[:capitals],
          hash[:digits])
    end

    def to_h
      {
          policy_name: @policy_name,
          min_length: @min_length,
          max_length: @max_length,
          special_chars: @special_chars,
          capitals: @capitals,
          digits: @digits
      }
    end

    def to_json
      JSON.generate(to_h)
    end

    def save(nsc)
      params = to_json
      AJAX.post(nsc, '/api/2.1/password_policy/', params, AJAX::CONTENT_TYPE::JSON)
    end

    def self.load(nsc)
      uri = '/api/2.1/password_policy/'
      resp = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash = JSON.parse(resp, symbolize_names: true)
      self.from_hash(hash)
    end
  end
end