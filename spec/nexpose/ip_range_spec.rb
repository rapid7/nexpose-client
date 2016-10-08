require 'spec_helper'

describe Nexpose::IPRange do
  describe '#<=>' do
    context 'with two from IP addresses' do
      it 'returns -1 when the first from address is less than the second' do
        first = Nexpose::IPRange.new('192.168.1.0')
        second = Nexpose::IPRange.new('192.168.1.1')
        expect(first).to be < second
      end
    end

    context 'with two from IP address and one to IP address' do
      it 'returns 0 when the first from address is equal to the second' do
        first = Nexpose::IPRange.new('192.168.1.0')
        second = Nexpose::IPRange.new('192.168.1.0')

        # TODO: IPRange#== is currently overridden instead of being defined by
        # IPRange#<=>
        expect(first <=> second).to be_zero
      end
    end

    context 'with one from IP address' do
      it 'returns 1 when the first from address is greater than the second' do
        first = Nexpose::IPRange.new('192.168.1.1')
        second = Nexpose::IPRange.new('192.168.1.0')
        expect(first).to be > second
      end
    end
  end
  describe '#include?' do
    context 'with IPAddr argument' do
      let(:ip_range) { Nexpose::IPRange.new('192.168.1.64','192.168.1.127') }
      it 'returns a false for valid IPv4 IPAddr outside of range' do
        ipv4_outside = IPAddr.new('192.168.1.1')
        expect(ip_range.include?(ipv4_outside)).to be_falsey
      end
      it 'returns a true for valid IPv4 IPAddr inside range' do
        ipv4_inside = IPAddr.new('192.168.1.65')
        expect(ip_range.include?(ipv4_inside)).to be_truthy
      end
      it 'returns a false for valid IPv4 network IPAddr outside of range' do
        ipv4_network = IPAddr.new('192.168.1.0/29')
        expect(ip_range.include?(ipv4_network)).to be_falsey
      end
      it 'returns a true for valid IPv4 IPAddr inside range' do
        ipv4_network = IPAddr.new('192.168.1.64/29')
        expect(ip_range.include?(ipv4_network)).to be_truthy
      end
    end
    context 'with a Nexpose::IPRange argument' do
      let(:ip_range) { Nexpose::IPRange.new('192.168.1.64','192.168.1.127') }
      it 'returns true for single address IPRange bounded by #from and #to' do
        other_single_iprange = Nexpose::IPRange.new('192.168.1.65')
        expect(ip_range.include?(other_single_iprange)).to be_truthy
      end
      it 'returns false for single address IPRange not bounded by #from and #to' do
        other_single_iprange = Nexpose::IPRange.new('192.168.1.1')
        expect(ip_range.include?(other_single_iprange)).to be_falsey
      end
      it 'returns a true for multiple address IPRange bounded by #from and #to' do
        other_multiple_iprange = Nexpose::IPRange.new('192.168.1.65', '192.168.1.100')
        expect(ip_range.include?(other_multiple_iprange)).to be_truthy
      end
      it 'returns a false for multiple address IPRange not bounded by #from and #to' do
        other_multiple_iprange = Nexpose::IPRange.new('192.168.1.1', '192.168.1.100')
        expect(ip_range.include?(other_multiple_iprange)).to be_falsey
      end
    end
    context 'with a castable string argument' do
      let(:ip_range) { Nexpose::IPRange.new('192.168.1.64','192.168.1.127') }
      it 'returns true for single IPv4 addresses bounded by #from and #to' do
        other_host_string = '192.168.1.90'
        expect(ip_range.include?(other_host_string)).to be_truthy
      end
      it 'returns false for single IPv4 addresses not bounded by #from and #to' do
        other_host_string = '192.168.1.200'
        expect(ip_range.include?(other_host_string)).to be_falsey
      end
      it 'returns true for masked IPv4 addresses bounded by #from and #to' do
        other_cidr_string = '192.168.1.96/29'
        expect(ip_range.include?(other_cidr_string)).to be_truthy
      end
      it 'returns false for masked IPv4 addresses not bounded by #from and #to' do
        other_cidr_string = '192.168.1.0/24'
        expect(ip_range.include?(other_cidr_string)).to be_falsey
      end
    end
    context 'with an uncastable argument' do
      let(:range) { Nexpose::IPRange.new('192.168.1.64','192.168.1.127') }
      it 'returns false for stringlike arguments that cannot be coerced' do
        uncastable = 'kitten'
        expect(range.include?(uncastable)).to be_falsey
      end
      it 'prints warning for stringlike arguments that raise IPAddr::InvalidAddressError' do
        uncastable = 'kitten'
        expect { range.include?(uncastable) }.to output(/could not coerce/).to_stderr
      end
      it 'returns false for stringlike arguments that raise IPAddr::AddressFamilyError' do
        uncastable = '0'
        expect { range.include?(uncastable) }.to output(/could not coerce/).to_stderr
      end
      it 'returns false for intlike arguments that cannot be coerced' do
        unusable = 0
        expect { range.include?(unusable) }.to raise_error(ArgumentError,/invalid type/)
      end
    end
  end
  describe '#include_ipaddr?' do
    context 'calling from a range of one ip' do
      context 'with a /32 argument' do
        let(:single) { Nexpose::IPRange.new('192.168.1.1') }
        it 'returns false if the other ip is not equal' do
          other = IPAddr.new('192.168.1.2')
          expect(single.send(:include_ipaddr?,other)).to be_falsey
        end
        it 'returns true if the other ip is equal' do
          other = IPAddr.new('192.168.1.1')
          expect(single.send(:include_ipaddr?,other)).to be_truthy
        end
      end
      context 'with a CIDR network argument ' do
        let(:single_aligned) { Nexpose::IPRange.new('192.168.1.0') }
        it 'returns false if self.from == other base and masklen != 32' do
          cidr_28 = IPAddr.new('192.168.1.0/28')
          expect(single_aligned.send(:include_ipaddr?,cidr_28)).to be_falsey
        end
        it 'returns false if self.from != other base and masklen != 32' do
          cidr_28_succ = IPAddr.new('192.168.1.1/28')
          expect(single_aligned.send(:include_ipaddr?,cidr_28_succ)).to be_falsey
        end

        it 'returns true if self.from == other base and masklen == 32' do
          cidr_32 = IPAddr.new('192.168.1.0/32')
          expect(single_aligned.send(:include_ipaddr?,cidr_32)).to be_truthy
        end
        it 'returns false if self.from != other base and masklen == 32' do
          cidr_32_succ = IPAddr.new('192.168.1.1/32')
          expect(single_aligned.send(:include_ipaddr?,cidr_32_succ)).to be_falsey
        end
      end
      context 'with an IPv6 address' do
        let(:single) { Nexpose::IPRange.new('192.168.1.1') }
        it 'returns false for an IPv6 address' do
          ipv6 = IPAddr.new('2001:0:0:0:DB8:800:200C:417A')
          expect(single.send(:include_ipaddr?,ipv6)).to be_falsey
        end
        it 'returns false for an equivalent IPv6 address' do
          ipv6_equiv = IPAddr.new('0:0:0:0:0:0:c0a8:0101')
          expect(single.send(:include_ipaddr?,ipv6_equiv)).to be_falsey
        end
        it 'returns false for an ipv4 compatible IPv6 address' do
          ipv6_compat = IPAddr.new('192.168.1.1').ipv4_compat
          expect(single.send(:include_ipaddr?,ipv6_compat)).to be_falsey
        end
      end
    end
    context 'calling from a spanning range' do

      context 'with a single IPv4 argument' do
        let(:span_10_100) { Nexpose::IPRange.new('192.168.1.10','192.168.1.100') }
        it 'returns false if self.to < other' do
          outside_right = IPAddr.new('192.168.1.101')
          expect(span_10_100.send(:include_ipaddr?,outside_right)).to be_falsey
        end
        it 'returns false if self.from > other' do
          outside_left = IPAddr.new('192.168.1.1')
          expect(span_10_100.send(:include_ipaddr?,outside_left)).to be_falsey
        end
        it 'returns true if self.from==other' do
          equal_from = IPAddr.new('192.168.1.10')
          expect(span_10_100.send(:include_ipaddr?,equal_from)).to be_truthy
        end
        it 'returns true if self.to==other' do
          equal_to = IPAddr.new('192.168.1.100')
          expect(span_10_100.send(:include_ipaddr?,equal_to)).to be_truthy
        end
        it 'returns true if self.from < other < self.to' do
          inside = IPAddr.new('192.168.1.50')
          expect(span_10_100.send(:include_ipaddr?,inside)).to be_truthy
        end
      end
      context 'calling from an aligned range' do
        it 'returns true if self == other' do
          range = Nexpose::IPRange.new('192.168.1.64','192.168.1.127')
          same_cidr = IPAddr.new('192.168.1.64/26')
          expect(range.send(:include_ipaddr?,same_cidr)).to be_truthy
        end

        it 'returns false for uncovered left and uncovered right' do
          range = Nexpose::IPRange.new('192.168.1.64','192.168.1.127')
          uncovered_cidr = IPAddr.new('192.168.1.0/24')
          expect(range.send(:include_ipaddr?,uncovered_cidr)).to be_falsey
        end
        it 'returns false for uncovered left and equal right' do
          range = Nexpose::IPRange.new('192.168.1.64','192.168.1.127')
          uncovered_left_equal_right = IPAddr.new('192.168.1.64/25')
          expect(range.send(:include_ipaddr?,uncovered_left_equal_right)).to be_falsey
        end
        it 'returns false for equal left and uncovered right' do
          range = Nexpose::IPRange.new('192.168.1.0','192.168.1.127')
          equal_left_uncovered_right = IPAddr.new('192.168.1.0/24')
          expect(range.send(:include_ipaddr?,equal_left_uncovered_right)).to be_falsey
        end
        it 'returns false for included left and uncovered right' do
          range = Nexpose::IPRange.new('192.168.1.64','192.168.1.95')
          included_left_uncovered_right = IPAddr.new('192.168.1.65/26')
          expect(range.send(:include_ipaddr?, included_left_uncovered_right)).to be_falsey
        end
        it 'returns true for included left and equal right' do
          range = Nexpose::IPRange.new('192.168.1.64','192.168.1.95')
          included_left_equal_right = IPAddr.new('192.168.1.80/28')
          expect(range.send(:include_ipaddr?, included_left_equal_right)).to be_truthy
        end
        it 'returns true for equal left and included right'  do
          range = Nexpose::IPRange.new('192.168.1.64','192.168.1.95')
          equal_left_included_right = IPAddr.new('192.168.1.64/28')
          expect(range.send(:include_ipaddr?, equal_left_included_right)).to be_truthy
        end
        it 'returns true for included left and included right' do
          included_left_included_right = IPAddr.new('192.168.1.80/29')
          range = Nexpose::IPRange.new('192.168.1.64','192.168.1.95')
          expect(range.send(:include_ipaddr?, included_left_included_right)).to be_truthy
        end
      end
    end
  end
  describe '#include_iprange?' do
    context 'calling from a single ip' do
      let(:single) { Nexpose::IPRange.new('192.168.1.1') }
      it 'returns true if self.from == other.from and other.to.nil?' do
        other = Nexpose::IPRange.new('192.168.1.1')
        expect(single.send(:include_iprange?, other)).to be_truthy
      end
      it 'returns false for other.from < self.from and other.to.nil?'do
        other = Nexpose::IPRange.new('192.168.1.0')
        expect(single.send(:include_iprange?, other)).to be_falsey
      end
      it 'returns false for other.from > self.from and other.to.nil?' do
        other = Nexpose::IPRange.new('192.168.1.2')
        expect(single.send(:include_iprange?, other)).to be_falsey
      end
      it 'returns false for self.from == other.from and other.to not nil' do
        other = Nexpose::IPRange.new('192.168.1.1','192.168.1.2')
        expect(single.send(:include_iprange?, other)).to be_falsey
      end
      it 'returns false for self.from < other.from and other.to not nil' do
        other = Nexpose::IPRange.new('192.168.1.2','192.168.1.3')
        expect(single.send(:include_iprange?, other)).to be_falsey
      end
      it 'returns false for self.from > other.from and other.to not nil' do
        other = Nexpose::IPRange.new('192.168.1.0','192.168.1.1')
        expect(single.send(:include_iprange?, other)).to be_falsey
      end
    end
    context 'called from a spanning range' do
      let(:spanning) { Nexpose::IPRange.new('192.168.1.1','192.168.1.100') }
      it 'returns false for other.from < self.from' do
        uncovered_left = Nexpose::IPRange.new('192.168.1.0','192.168.1.2')
        expect(spanning.send(:include_iprange?, uncovered_left)).to be_falsey
      end
      it 'returns false for self.to < other.to' do
        uncovered_right = Nexpose::IPRange.new('192.168.1.2','192.168.1.105')
        expect(spanning.send(:include_iprange?, uncovered_right)).to be_falsey
      end
      it 'returns true for self.from < other.from && other.to < self.to'  do
        fully_included = Nexpose::IPRange.new('192.168.1.2','192.168.1.99')
        expect(spanning.send(:include_iprange?, fully_included)).to be_truthy
      end
      it 'returns true for self.from < other.from && other.to == self.to'  do
        same_right = Nexpose::IPRange.new('192.168.1.2','192.168.1.100')
        expect(spanning.send(:include_iprange?, same_right)).to be_truthy
      end
      it 'returns true for self.from == other.from && other.to < self.to'  do
        same_left = Nexpose::IPRange.new('192.168.1.1','192.168.1.3')
        expect(spanning.send(:include_iprange?, same_left)).to be_truthy
      end
      it 'returns true for self==other' do
        same = Nexpose::IPRange.new('192.168.1.1','192.168.1.100')
        expect(spanning.send(:include_iprange?, same)).to be_truthy
      end
    end
  end

  describe '#as_xml' do
    include Helpers::XML

    context 'with a single IP address' do
      subject { Nexpose::IPRange.new('192.168.1.0').as_xml }

      it 'creates a range node with from and to parameters' do
        expect(subject).to have_name('range')

        attributes = attributes_to_hash(subject.attributes)
        expect(attributes).to include('from' => '192.168.1.0')
        expect(attributes['to']).to be_nil
      end
    end

    context 'with multiple IP addresses' do
      subject { Nexpose::IPRange.new('192.168.1.0', '192.168.1.255').as_xml }

      it 'creates a range node with from and to parameters' do
        expect(subject).to have_name('range')

        attributes = attributes_to_hash(subject.attributes)
        expect(attributes).to include(
          'from' => '192.168.1.0',
          'to' => '192.168.1.255'
        )
      end
    end

    context 'with a CIDR notation IP range' do
      subject { Nexpose::IPRange.new('192.168.1.0/24').as_xml }

      it 'creates a range node with from and to parameters' do
        expect(subject).to have_name('range')

        attributes = attributes_to_hash(subject.attributes)
        expect(attributes).to include(
          'from' => '192.168.1.0',
          'to' => '192.168.1.255'
        )
      end
    end
  end

  describe '#size' do
    context 'with a single IP address' do
      subject { Nexpose::IPRange.new('192.168.1.0') }

      it 'returns one' do
        expect(subject.size).to eq(1)
      end
    end

    context 'with multiple IP addresses' do
      subject { Nexpose::IPRange.new('192.168.1.0', '192.168.1.255') }

      it 'returns 256' do
        expect(subject.size).to eq(256)
      end
    end

    context 'with a CIDR notation IP range' do
      subject { Nexpose::IPRange.new('192.168.1.0/24') }

      it 'returns 256' do
        expect(subject.size).to eq(256)
      end
    end
  end
end
