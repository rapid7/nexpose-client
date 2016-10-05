module Nexpose
  # Object that represents a single IP address or an inclusive range of IP addresses.
  # If to is nil then the from field will be used to specify a single IP Address only.
  #
  class IPRange
    # Start of range *Required
    attr_accessor :from
    # End of range *Optional (If nil then IPRange is a single IP Address)
    attr_accessor :to

    # @overload initialize(ip)
    #   @param [#to_s] from the IP single IP address.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0')
    #
    # @overload initialize(start_ip, end_ip)
    #   @param [#to_s] from the IP to start the range with.
    #   @param [#to_s] to the IP to end the range with.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0', '192.168.1.255')
    #
    # @overload initialize(cidr_range)
    #   @param [#to_s] from the CIDR notation IP address range.
    #   @example
    #     Nexpose::IPRange.new('192.168.1.0/24')
    #   @note The range will not be stripped of reserved IP addresses (such as
    #     x.x.x.0 and x.x.x.255).
    #
    # @return [IPRange] an IP address range of one or more addresses.
    def initialize(from, to = nil)
      @from = from
      @to = to unless from == to

      return unless @to.nil?

      range = IPAddr.new(@from.to_s).to_range
      unless range.one?
        @from = range.first.to_s
        @to = range.last.to_s
      end
    end

    # Size of the IP range. The total number of IP addresses represented
    # by this range.
    #
    # @return [Fixnum] size of the range.
    #
    def size
      return 1 if @to.nil?
      from = IPAddr.new(@from)
      to = IPAddr.new(@to)
      (from..to).to_a.size
    end

    include Comparable

    def <=>(other)
      return 1 unless other.respond_to? :from
      from = IPAddr.new(@from)
      to = @to.nil? ? from : IPAddr.new(@to)
      cf_from = IPAddr.new(other.from)
      cf_to = IPAddr.new(other.to.nil? ? other.from : other.to)
      if cf_to < from
        1
      elsif to < cf_from
        -1
      else # Overlapping
        0
      end
    end

    def ==(other)
      eql?(other)
    end

    def eql?(other)
      return false unless other.respond_to? :from
      @from == other.from && @to == other.to
    end

    #
    # @overload include?(other)
    #   @param other [IPAddr] /32 IP address
    #
    # @overload include?(IPAddr)
    #   @param other [IPAddr] CIDR range
    #
    # @overload include?(other)
    #   @param other [IPRange] single IP address
    #
    # @overload include?(other)
    #   @param other [IPRange] IPRange spanning multiple IPs
    #
    # @overload include?(other)
    #   @param other [String] /32 IP address
    #
    # @overload include?(other)
    #   @param other [String] CIDR range
    #
    # @return [FalseClass]|[TrueClass] if other is bounded inclusively by #from and #to
    #
    def include?(other)
      case other
      when IPAddr
        include_ipaddr?(other)
      when Nexpose::IPRange
        include_iprange?(other)
      when String
        begin
          other_addr = IPAddr.new(other)
        rescue IPAddr::InvalidAddressError => invalid_address
         warn "could not coerce \"#{other}\" to IPAddr at #{invalid_address.backtrace[0]}: #{invalid_address.cause.to_s}"
          return false
        rescue IPAddr::AddressFamilyError => address_family
          warn "could not coerce \"#{other}\" to IPAddr at #{address_family.backtrace[0]}: #{address_family.cause.to_s}"
          return false
        end
        include_ipaddr?(other_addr)
      else
        raise ArgumentError, "invalid type: #{other.class.to_s} not one of IPAddr, String, Nexpose::IPRange"
      end
    end

    def hash
      to_xml.hash
    end

    def as_xml
      xml = REXML::Element.new('range')
      xml.add_attributes({ 'from' => @from, 'to' => @to })
      xml
    end
    alias_method :to_xml_elem, :as_xml

    def to_xml
      as_xml.to_s
    end

    def to_s
      return from.to_s if to.nil?
      "#{from.to_s} - #{to.to_s}"
    end

    def include_ipaddr?(other)
      other_range = other.to_range
      other_from  = other_range.first
      other_to    = other_range.last
      other_iprange = Nexpose::IPRange.new(other_from.to_s, other_to.to_s)
      include_iprange?(other_iprange)
    end

    def include_iprange?(other)
      if (other.to==nil) && (self.to==nil)
        eql?(other)
      elsif (other.to!=nil) && (self.to==nil)
        false
      elsif (other.to==nil) && (self.to!=nil)
        ip_from    = IPAddr.new(self.from)
        ip_to      = IPAddr.new(self.to)
        other_from = IPAddr.new(other.from)
        (ip_from <= other_from) && (other_from <= ip_to)
      else
        ip_from    = IPAddr.new(self.from)
        ip_to      = IPAddr.new(self.to)
        other_from = IPAddr.new(other.from)
        other_to   = IPAddr.new(other.to)
        (ip_from <= other_from) && (other_to <= ip_to)
      end
    end
  end
end