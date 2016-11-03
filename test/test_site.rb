require 'rspec/given'

require 'rexml/document'
require 'nexpose'
include Nexpose

describe Site do

  # Stub object to return REXML response.
  class Response
    attr_accessor :res
    def initialize(res)
      @res = res
    end
  end

  # Add Response behavior to an Object.
  def add_response
    obj = Object.new
    class << obj
      def url
        Response.new(REXML::Document.new(File.open('site-config.xml')))
      end
      def session_id
        'FEDCBA'
      end
    end
    obj
  end

  # Failure from SiteConfigRequest
  def load_failure
    obj = Object.new
    class << obj
      def url
        Response.new(REXML::Document.new(File.open('site-load-failure.xml')))
      end
      def session_id
        'FEDCBA'
      end
    end
    obj
  end

  # Success from SiteDeleteRequest
  def delete_success
    obj = Object.new
    class << obj
      def session_id
        'FEDCBA'
      end
    end
    obj
  end

  # Failure from SiteDeleteRequest
  def delete_failure
    obj = Object.new
    class << obj
      def session_id
        'FAIL'
      end
    end
    obj
  end

  # Monkey patch API behavior to give static responses.
  class Nexpose::APIRequest
    def self.execute(url, trust_store, req, api_version='1.1')
      url
    end
  end

  # Load in Site object from configuration.
  def load_site
    nsc = add_response
    Site.load(nsc, 2)
  end

  context "default constructor" do
    When(:site) { Site.new }

    Then { site.id.should == -1 }
    Then { site.risk_factor.to_f.should == 1.0 }
    Then { site.scan_template.should == 'full-audit' }
  end

  context "constructor with arguments" do
    When(:site) { Site.new('name', 'web-audit') }

    Then { site.id.should == -1 }
    Then { site.risk_factor.to_f.should == 1.0 }
    Then { site.name.should == 'name' }
    Then { site.scan_template.should == 'web-audit' }
  end

  Given(:xml) { REXML::Document.new(File.open('site-config.xml')) }

  context "parse from xml" do
    When(:site) { Site.parse(xml) }

    Then { site.id.to_i.should == 2 }
    Then { site.assets.size.should == 3 }
    Then { site.schedules.size.should == 1 }
  end

  context "load a site: success" do
    When(:site) { load_site }

    Then { site.id.to_i.should == 2 }
    Then { site.assets.size.should == 3 }
    Then { site.schedules.size.should == 1 }
  end

  context "load a site: failure" do
    Given(:nsc) { load_failure }
    When(:site) { Site.load(nsc, 1337) }

    Then { site.should == nil }
  end

  context "copy a site" do
    Given(:nsc) { add_response }
    When(:site) { Site.copy(nsc, 2) }

    Then { site.id.to_i.should == -1 }
    Then { site.assets.size.should == 3 }
    Then { site.schedules.size.should == 1 }
  end

  context "save a site: success" do
  end

  context "save a site: failure" do
  end

  context "scan a site: success" do
  end

  context "scan a site: failure" do
  end

  context "delete a site: success" do
    Given(:site) { load_site}
    Given(:nsc) { delete_success }
    # When(:response) { site.delete(nsc) }

    # Then { response.should == true }
  end

  context "delete a site: failure" do
    Given(:site) { load_site}
    Given(:nsc) { delete_failure }
    # When(:response) { site.delete(nsc) }

    # Then { response.should == false }
  end
end
