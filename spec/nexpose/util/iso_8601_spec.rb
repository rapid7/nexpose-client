require 'spec_helper'

describe Nexpose::ISO8601 do
  subject { Nexpose::ISO8601 }
  let(:time_iso8601_string) { '20141210T165822.412Z' }
  let(:time) {
    # 412,000 (10^3 * 412) microseconds is equivalent to 412
    # nanoseconds which is used in "time_iso8601_string".
    microseconds = 412_000
    seconds = Time.new(2014, 12, 10, 16, 58, 22, 0).to_i
    Time.at(seconds, microseconds)
  }

  describe '.to_string' do
    it 'converts a Time object into an ISO 8601 string' do
      observed = subject.to_string(time)
      expect(observed).to eq(time_iso8601_string)
    end
  end

  describe '.to_time' do
    it 'converts an ISO 8601 string into a Time object' do
      observed = subject.to_time(time_iso8601_string)
      expect(observed).to eq(time)
    end
  end
end
