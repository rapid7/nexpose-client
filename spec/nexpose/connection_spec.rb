require 'spec_helper'

describe Nexpose::Connection do
  describe '.from_uri' do
    let(:username) { nil }
    let(:password) { nil }
    let(:silo_id) { nil }
    subject(:connection) { Nexpose::Connection.from_uri(uri, username, password, silo_id) }

    context 'with the default port' do
      let(:uri) { 'https://nexpose.local:3780/' }

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
end
