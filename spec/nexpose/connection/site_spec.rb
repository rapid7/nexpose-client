require 'spec_helper'

describe Nexpose::Connection, :vcr do
  let(:console_hostname) { ENV['NEXPOSE_HOSTNAME'] }
  let(:username) { ENV['NEXPOSE_USERNAME'] }
  let(:password) { ENV['NEXPOSE_PASSWORD'] }
  let(:connection) do
    Nexpose::Connection.new(console_hostname, username, password).tap(&:login)
  end

  describe 'Site methods' do
    describe '#sites' do
      attr_reader :expected_sites

      after do
        VCR.use_cassette('delete_basic_site') do
          basic_site.delete(connection)
        end
      end

      before do
        @expected_sites = [basic_site]
      end

      let(:basic_site) do
        Nexpose::Site.new('test site name 1').tap do |site|
          site.description = 'test site description 1'

          VCR.use_cassette('basic_site') do
            site.save(connection)
          end
        end
      end

      it 'returns a list of site summaries' do
        sites = VCR.use_cassette('site_listing') { connection.sites }
        expected_sites.map! do
          a_site_matching(
            name: basic_site.name,
            description: basic_site.description
          )
        end

        expect(sites).to include(*expected_sites)
      end
    end
  end
end
