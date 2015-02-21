require 'spec_helper'

describe Nexpose::Site do
  let(:scan_template) { 'full-audit-without-webspider' }
  let(:site_name) { 'joe blow site' }
  subject { Nexpose::Site.new(site_name, scan_template) }

  describe '#add_asset' do
    context 'with a hostname' do
      it 'adds a new HostName to the assets list' do
        subject.add_asset('nexpose.local')

        expect(subject.assets).to include(Nexpose::HostName.new('nexpose.local'))
      end
    end

    context 'with a single IP address' do
      it 'adds a new IPRange to the assets list' do
        subject.add_asset('192.168.1.1')

        expect(subject.assets).to include(Nexpose::IPRange.new('192.168.1.1'))
      end
    end

    context 'with a multiple IP address' do
      # TODO: The IPRange class apparently doesn't handle CIDR notation on the client side
      xit 'adds a new IPRange to the assets list' do
        subject.add_asset('192.168.1.0/24')

        expect(subject.assets).to include(Nexpose::IPRange.new('192.168.1.0', '192.168.1.255'))
      end
    end
  end

  describe '#add_host' do
    it 'adds a new HostName to the assets list' do
      subject.add_asset('nexpose.local')

      expect(subject.assets).to include(Nexpose::HostName.new('nexpose.local'))
    end
  end

  describe '#add_ip' do
    context 'with a single IP address' do
      it 'adds a new IPRange to the assets list' do
        subject.add_asset('192.168.1.1')

        expect(subject.assets).to include(Nexpose::IPRange.new('192.168.1.1'))
      end
    end

    context 'with a multiple IP address' do
      # TODO: The IPRange class apparently doesn't handle CIDR notation on the client side
      xit 'adds a new IPRange to the assets list' do
        subject.add_asset('192.168.1.0/24')

        expect(subject.assets).to include(Nexpose::IPRange.new('192.168.1.0', '192.168.1.255'))
      end
    end
  end

  context 'with assets' do
    before do
      subject.assets = [
        Nexpose::IPRange.new('192.168.1.1'),
        Nexpose::IPRange.new('192.168.1.0', '192.168.1.255'),
        Nexpose::IPRange.new('192.168.1.1/24'),
        Nexpose::HostName.new('nexpose.local')
      ]
    end

    describe '#remove_asset' do
      context 'with a hostname' do
        it 'removes a new HostName from the assets list' do
          subject.remove_asset('nexpose.local')

          expect(subject.assets)
            .to_not include(Nexpose::HostName.new('nexpose.local'))
        end
      end

      context 'with a single IP address' do
        it 'removes a new IPRange from the assets list' do
          subject.remove_asset('192.168.1.1')

          expect(subject.assets)
            .to_not include(Nexpose::IPRange.new('192.168.1.1'))
        end
      end

      context 'with a multiple IP address' do
        # TODO: The IPRange class apparently doesn't handle CIDR notation on
        # the client side.
        xit 'removes a new IPRange from the assets list' do
          subject.remove_asset('192.168.1.0/24')

          expected_asset = Nexpose::IPRange.new('192.168.1.0', '192.168.1.255')
          expect(subject.assets).to_not include(expected_asset)
        end
      end
    end

    describe '#remove_host' do
      it 'removes a new HostName from the assets list' do
        subject.remove_asset('nexpose.local')

        expect(subject.assets)
          .to_not include(Nexpose::HostName.new('nexpose.local'))
      end
    end

    describe '#remove_ip' do
      context 'with a single IP address' do
        it 'removes a new IPRange from the assets list' do
          subject.remove_asset('192.168.1.1')

          expect(subject.assets)
            .to_not include(Nexpose::IPRange.new('192.168.1.1'))
        end
      end

      context 'with a multiple IP address' do
        # TODO: The IPRange class apparently doesn't handle CIDR notation on
        # the client side.
        xit 'adds a new IPRange to the assets list' do
          subject.remove_asset('192.168.1.0/24')

          expect(subject.assets)
            .to_not include(Nexpose::IPRange.new('192.168.1.0/24'))
        end
      end
    end
  end
end
