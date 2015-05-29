require 'spec_helper'

describe Nexpose::DiscoveryConnection do
  describe '#save' do
    context 'for a new discovery connection' do
      subject do
        discovery_connection = Nexpose::DiscoveryConnection.new("test-discovery-connection-#{Time.now.to_i}", 'example-host.local', 'johndoe', 'password123')
      end

      it 'sends a request to create the connection' do
        xml = REXML::Element.new(%(<DiscoveryConnectionCreateResponse id="1"></DiscoveryConnectionCreateResponse>))
       response = double(:response, res: xml, success: true)
        nexpose_connection = Nexpose::Connection.new('example-host.local', 'johndoe', 'password123')
        expect(nexpose_connection).to receive(:make_xml)
          .with('DiscoveryConnectionCreateRequest')
          .and_call_original
        allow(nexpose_connection).to receive(:execute).and_return(response)

        subject.save(nexpose_connection)
      end
    end

    context 'for a discovery connection with an id' do
      subject do
        discovery_connection = Nexpose::DiscoveryConnection.new("test-discovery-connection-#{Time.now.to_i}", 'example-host.local', 'johndoe', 'password123')

        discovery_connection.id = 1

        discovery_connection
      end

      it 'sends a request to update the connection' do
        xml = REXML::Element.new(%(<DiscoveryConnectionUpdateResponse id="1"></DiscoveryConnectionUpdateResponse>))
        response = double(:response, res: xml, success: true)
        nexpose_connection = Nexpose::Connection.new('example-host.local', 'johndoe', 'password123')
        expect(nexpose_connection).to receive(:make_xml)
          .with('DiscoveryConnectionUpdateRequest')
          .and_call_original
        allow(nexpose_connection).to receive(:execute).and_return(response)

        subject.save(nexpose_connection)
      end
    end
  end
end
