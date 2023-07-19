require 'spec_helper'

describe Nexpose::AJAX do
  let(:console_hostname) { 'on-prem.nexpose.company.int' }
  let(:username) { 'admin' }
  let(:password) { 'password' }
  let(:connect_host) { nil }
  let(:connection_timeout) { 120 }
  let(:open_timeout) { 120 }
  let(:trust_store) { nil }
  let(:port) { 3780 }
  let(:connection) do
    double('Nexpose::Connection', host: console_hostname, port: port, timeout: connection_timeout, open_timeout: open_timeout,
                                  connect_host: connect_host, trust_store: trust_store)
  end
  let(:timeout) { nil }

  subject!(:https) { Nexpose::AJAX.https(connection, timeout) }

  describe '#https' do
    context 'using connection defaults' do
      it 'disables cert verification' do
        expect(https.verify_mode).to eq(OpenSSL::SSL::VERIFY_NONE)
        expect(https.cert_store).to be_nil
      end

      it 'uses connection default timeout' do
        expect(https.read_timeout).to eq(connection.timeout)
      end

      it 'sets http hostname and port from connection' do
        expect(https.address).to eq(connection.host)
        expect(https.port).to eq(connection.port)
      end

      it 'leaves ipaddr nil' do
        expect(https.ipaddr).to be_nil
      end
    end

    context 'connect_host is provided in the connection' do
      let(:connect_host) { 'virtual-tunnel.us.kennasec.com' }

      it 'sets ipaddr on the Net::HTTPS' do
        expect(https.ipaddr).to eq(connect_host)
      end
    end

    context 'timeout is provided in the call' do
      let(:timeout) { 240 }

      it 'sets timeout from the method call' do
        expect(https.read_timeout).to eq(timeout)
      end
    end

    context 'cert_store is provided in the connection' do
      let(:trust_store) { OpenSSL::X509::Store.new }

      it 'sets http cert store' do
        expect(https.cert_store).to equal(trust_store)
      end
    end
  end
end
