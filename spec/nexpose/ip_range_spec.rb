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
    shared_examples_for 'covered compatible type' do |host_addr|
      it 'returns true for IPAddr arguments' do
        other = IPAddr.new(host_addr)
        expect(iprange.include?(other)).to be_truthy
      end
      it 'returns true for Nexpose::IPRange arguments' do
        other = Nexpose::IPRange.new(host_addr)
        expect(iprange.include?(other)).to be_truthy
      end
      it 'returns true for String arguments' do
        other = host_addr
        expect(iprange.include?(other)).to be_truthy
      end
    end

    shared_examples_for 'uncovered compatible type' do |host_addr|
      it 'returns false for IPAddr arguments' do
        other = IPAddr.new(host_addr)
        expect(iprange.include?(other)).to be_falsey
      end
      it 'returns false for Nexpose::IPRange arguments' do
        other = Nexpose::IPRange.new(host_addr)
        expect(iprange.include?(other)).to be_falsey
      end
      it 'returns false for String arguments' do
        other = host_addr
        expect(iprange.include?(other)).to be_falsey
      end
    end

    shared_examples_for 'uncovered address' do |other|
      it 'returns false' do
        expect(iprange.include?(other)).to be_falsey
      end
    end

    shared_examples_for 'covered address' do |other|
      it 'returns true' do
        expect(iprange.include?(other)).to be_truthy
      end
    end

    shared_examples_for 'uncastable string' do |unusable_string|
      it 'only works on strings' do
        expect(unusable_string).to be_a(String)
      end

      it 'returns false' do
        expect(iprange.include?(unusable_string)).to be_falsey
      end

      it 'traps exceptions from IPAddr.initialize' do
        expect { iprange.include?(unusable_string) }.not_to raise_error
      end

      it 'emits a warning to stderr' do
        expect { iprange.include?(unusable_string) }.to output(/could not coerce/).to_stderr
      end
    end

    shared_examples_for 'incompatible type' do |other|
      it 'raises an ArgumentError' do
        expect { iprange.include?(other) }.to raise_error(ArgumentError, /incompatible type/)
      end
    end

    context 'when IPRange contains a single address' do
      let(:iprange) { Nexpose::IPRange.new('192.168.1.81') }

      below_subject = '192.168.1.80'
      above_subject = '192.168.1.82'
      uncovered_cidr = '192.168.1.64/28'
      equivalent = '192.168.1.81'
      covered_cidr = '192.168.1.81/32'

      it_behaves_like 'covered compatible type', equivalent

      it_behaves_like 'uncovered compatible type', below_subject
      it_behaves_like 'uncovered compatible type', above_subject
      it_behaves_like 'uncovered compatible type', uncovered_cidr

      it_behaves_like 'covered address', Nexpose::IPRange.new(equivalent, equivalent)
      it_behaves_like 'covered address', Nexpose::IPRange.new(equivalent)
      it_behaves_like 'covered address', Nexpose::IPRange.new(equivalent, nil)
      it_behaves_like 'covered address', covered_cidr
      it_behaves_like 'covered address', IPAddr.new(covered_cidr)

      it_behaves_like 'uncovered address', Nexpose::IPRange.new(below_subject, equivalent)
      it_behaves_like 'uncovered address', Nexpose::IPRange.new(equivalent, above_subject)
      it_behaves_like 'uncovered address', Nexpose::IPRange.new(below_subject, above_subject)

      context 'making invalid comparisons' do
        it_behaves_like 'uncastable string', 'kitten'
        it_behaves_like 'uncastable string', '0'
        it_behaves_like 'incompatible type', 0
        it_behaves_like 'incompatible type', :kitten
        it_behaves_like 'incompatible type', nil
      end
    end

    context 'when IPRange spans multiple addresses' do
      let(:iprange) { Nexpose::IPRange.new('192.168.1.64', '192.168.1.95') }

      covered_cidr = '192.168.1.72/30'
      equivalent_cidr = '192.168.1.64/27'

      lower_bound = '192.168.1.64'
      upper_bound = '192.168.1.95'
      below_subject = '192.168.1.63'
      above_subject = '192.168.1.96'
      inside_subject = '192.168.1.65'

      included_cidr_same_right = '192.168.1.88/29'
      included_cidr_same_left = '192.168.1.64/29'
      uncovered_cidr_same_left = '192.168.1.64/26'
      uncovered_cidr = '192.168.1.0/25'

      context 'comparing bounded address' do
        it_behaves_like 'covered compatible type', equivalent_cidr
        it_behaves_like 'covered compatible type', lower_bound
        it_behaves_like 'covered compatible type', upper_bound
        it_behaves_like 'covered compatible type', inside_subject
      end
      context 'comparing bounded cidr' do
        it_behaves_like 'covered compatible type', covered_cidr
        it_behaves_like 'covered compatible type', included_cidr_same_left
        it_behaves_like 'covered compatible type', included_cidr_same_right
      end

      context 'comparing bounded Nexpose::IPRange' do
        it_behaves_like 'covered address', Nexpose::IPRange.new(lower_bound, upper_bound)
        it_behaves_like 'covered address', Nexpose::IPRange.new(lower_bound, inside_subject)
        it_behaves_like 'covered address', Nexpose::IPRange.new(inside_subject, upper_bound)
      end

      context 'comparing unbounded address' do
        it_behaves_like 'uncovered compatible type', below_subject
        it_behaves_like 'uncovered compatible type', above_subject
      end

      context 'comparing unbounded cidr' do
        it_behaves_like 'uncovered compatible type', uncovered_cidr
        it_behaves_like 'uncovered compatible type', uncovered_cidr_same_left
      end

      context 'comparing unbounded Nexpose::IPRange' do
        it_behaves_like 'uncovered address', Nexpose::IPRange.new(below_subject, lower_bound)
        it_behaves_like 'uncovered address', Nexpose::IPRange.new(below_subject, upper_bound)
        it_behaves_like 'uncovered address', Nexpose::IPRange.new(below_subject, inside_subject)
        it_behaves_like 'uncovered address', Nexpose::IPRange.new(below_subject, above_subject)
        it_behaves_like 'uncovered address', Nexpose::IPRange.new(lower_bound, above_subject)
        it_behaves_like 'uncovered address', Nexpose::IPRange.new(inside_subject, above_subject)
      end

      context 'making invalid comparisons' do
        it_behaves_like 'uncastable string', 'kitten'
        it_behaves_like 'uncastable string', '0'
        it_behaves_like 'incompatible type', 0
        it_behaves_like 'incompatible type', :kitten
        it_behaves_like 'incompatible type', nil
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
