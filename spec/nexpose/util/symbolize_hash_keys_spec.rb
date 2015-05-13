require 'spec_helper'
require 'helpers'

describe Nexpose::SymbolizeHashKeys do
  subject { Nexpose::SymbolizeHashKeys }

  describe '.symbolize' do
    it 'converts all keys of a hash to symbols' do
      attributes = { "rad" => "nope", "rad2" => "nope2" }
      observed = subject.symbolize(attributes)

      expect(observed.keys).to all( be_an(Symbol) )
    end
  end

  describe 'nested hashes using .symbolize' do
    it 'converts all nested keys of a hash to symbols' do
      attributes = { "one" => "nope", "two" => { "three" => "deep", "four" => [{"five" => { "six" => "deep" }, "seven" => "town" }] } }
      observed = subject.symbolize(attributes)

      all_keys = Helpers::HashKeys.get_all_keys(observed)
      expect(all_keys).to all( be_an(Symbol) )
    end
  end

  describe 'fixnum keys using .symbolize' do
    it 'fails to convert fixnum to symbols' do
      attributes = { 0 => "nope" }
      observed = subject.symbolize(attributes)

      expect(observed.keys).not_to be_an(Symbol)
    end
  end


end
