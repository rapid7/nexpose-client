require 'spec_helper'

describe Nexpose::AssetGroup do
  let(:console_hostname) { 'on-prem.nexpose.company.int' }
  let(:port) { 3780 }
  let(:url) { "https://#{console_hostname}:#{port}/api/API_VERSION/xml" }
  let(:username) { 'admin' }
  let(:password) { 'password' }
  let(:connect_host) { nil }
  let(:connection_timeout) { 120 }
  let(:open_timeout) { 120 }
  let(:trust_store) { nil }

  let(:connection) { double('Nexpose::Connection', :host => console_hostname, :port => port, :timeout => connection_timeout, :open_timeout => open_timeout, :url => url, :connect_host => connect_host, :trust_store => trust_store, :session_id => 'asdf')
  }
  let(:group_id) { 52 }
  before do
    allow(Nexpose::APIRequest).to receive(:execute).and_return( double('nexpose_resonse', :res => "<AssetGroupConfigResponse><AssetGroup></AssetGroup></AssetGroupConfigResponse>") )
    allow(Nexpose::AssetGroup).to receive(:parse).and_return( Nexpose::AssetGroup.new('test group name', 'asset group for testing', group_id, 1000.0) )
  end
  subject!{ Nexpose::AssetGroup.load(connection, group_id) }

  describe 'self.load' do
      context 'with default connection parameters' do
        it 'executes and APIRequest without connect_host' do
          expect(Nexpose::APIRequest).to have_received(:execute).with(connection.url, %(<AssetGroupConfigRequest session-id="asdf" group-id="52"/>), '1.1', { timeout: connection.timeout, open_timeout: connection.open_timeout }, nil, nil)
        end
      end

      context 'with connect_host provided in connection' do
        let(:connect_host) { 'virtual-tunnel.us.kennasec.com' }

        it 'executes an APIRequest with connect_host' do
          expect(Nexpose::APIRequest).to have_received(:execute).with(connection.url, %(<AssetGroupConfigRequest session-id="asdf" group-id="52"/>), '1.1', { timeout: connection.timeout, open_timeout: connection.open_timeout }, nil, connect_host)
        end
      end
  end
end