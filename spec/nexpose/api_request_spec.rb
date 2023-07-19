require 'spec_helper'

describe Nexpose::APIRequest do
  let(:console_hostname) { 'on-prem.nexpose.company.int' }
  let(:port) { 3780 }
  let(:url) { "https://#{console_hostname}:#{port}/api/API_VERSION/xml" }
  let(:username) { 'admin' }
  let(:password) { 'password' }
  let(:connect_host) { nil }
  let(:connection_timeout) { 120 }
  let(:open_timeout) { 120 }
  let(:trust_store) { nil }
  let(:request_xml) { "" }


  describe '#new' do
    subject!(:api_request){ Nexpose::APIRequest.new(request_xml, url, '1,1', trust_store, connect_host) }
  
    context 'with defaults' do
      it 'creates a Net::HTTP with no ipaddr' do
        expect(api_request.http.ipaddr).to eq(nil)
      end
    end

    context 'with connect_host provided' do
      let(:connect_host) { 'virtual-tunnel.us.kennasec.com' }

      it 'creates a Net::HTTP with ipaddr parameter' do
        expect(api_request.http.ipaddr).to eq(connect_host)
      end
    end
  end

  describe 'execute' do
    let(:options){ {:timeout => 120, :open_timeout => 120, :raw => true} }
    let(:request_object) { Nexpose::APIRequest.new(request_xml, url, '1.1', trust_store, connect_host) }
    before do
      allow(Nexpose::APIRequest).to receive(:new).and_return( request_object )
      allow(request_object).to receive(:execute)
      allow(request_object).to receive(:success).and_return(true)
    end
    subject!(:returned_request) { Nexpose::APIRequest.execute(url, request_xml, '1.1', options, trust_store, connect_host) }

    context 'with defaults' do
      it 'creates a Net::HTTP with no ipadidr' do
        expect(returned_request.http.ipaddr).to eq(nil)
      end
      it 'executes the request' do
        expect(request_object).to have_received(:execute)
      end
    end

    context 'with connect_host provided' do
      let(:connect_host) { 'virtual-tunnel.us.kennasec.com' }

      it 'creates a Net::HTTP with ipaddr parameter' do
        expect(returned_request.http.ipaddr).to eq(connect_host)
      end
      it 'executes the request' do
        expect(request_object).to have_received(:execute)
      end
    end
  end
end