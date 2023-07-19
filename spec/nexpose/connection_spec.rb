require 'spec_helper'

describe Nexpose::Connection do
  let(:uri) { 'https://nexpose.local:3780/' }
  let(:username) { nil }
  let(:password) { nil }
  let(:silo_id) { nil }
  let(:connect_host) { nil }
  let(:token) { nil }
  let(:trust_cert) { nil }
  let(:port) { nil }

  describe '#new' do
    subject(:connection) { Nexpose::Connection.new(uri, username, password, port, silo_id, token, trust_cert, connect_host) }

    context 'with default connection params' do
      it 'has no connect_host attribute value' do
        expect(connection.connect_host).to be_nil
      end
    end

    context 'with connect_host provided' do
      let(:connect_host) { 'virtual-tunnel.us.kennasec.com' }

      it 'sets connect_host attribute' do
        expect(connection.connect_host).to equal(connect_host)
      end
    end
  end

  describe '.from_uri' do
    subject(:connection) { Nexpose::Connection.from_uri(uri, username, password, silo_id) }

    context 'with the default port' do
      it 'initializes a new Connection' do
        expect(connection.host).to eq('nexpose.local')
        expect(connection.password).to eq(password)
        expect(connection.port).to eq(3780)
        expect(connection.username).to eq(username)
      end
    end

    context 'with a non-default port' do
      let(:uri) { 'https://nexpose.local:1234/' }

      it 'initializes a new Connection' do
        expect(connection.host).to eq('nexpose.local')
        expect(connection.password).to eq(password)
        expect(connection.port).to eq(1234)
        expect(connection.username).to eq(username)
      end
    end
  end

  describe '#execute' do
    let(:connection) { Nexpose::Connection.new(uri, username, password, port, silo_id, token, trust_cert, connect_host) }
    let(:test_xml) { "<LoginRequest password='password' sync-id='0' user-id='username'></LoginRequest>" }
    let(:options) { {} }
    
    before do 
      allow(Nexpose::APIRequest).to receive(:execute).and_return( double(raw_response_data: 'success') )
    end

    subject!(:execute_response) { connection.execute(test_xml, nil, options) }

    context 'with default connection params' do
      it 'calls APIRequest#execute without connect_host' do
        expect(Nexpose::APIRequest).to have_received(:execute).with(connection.url, test_xml.to_s, nil, options, trust_cert, nil)
      end
    end

    context 'with connect_host defined' do
      let(:connect_host) { 'virtual-tunnel.us.kennasec.com' }

      it 'calls APIRequest#execute with connect_host parameter' do
        expect(Nexpose::APIRequest).to have_received(:execute).with(connection.url, test_xml.to_s, nil, options, trust_cert, connect_host)
      end
    end

    context 'with only request xml provided' do
      subject!(:execute_response) { connection.execute(test_xml) }

      it 'request defaults timeouts and api version' do
        expect(Nexpose::APIRequest).to have_received(:execute).with(connection.url, test_xml.to_s, '1.1', {:open_timeout=>120, :timeout=>120}, trust_cert, connect_host)
      end
    end
  end
end
