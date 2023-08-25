require 'uri'
module As2
  module Config
    def self.build_certificate(input)
      if input.kind_of? OpenSSL::X509::Certificate
        input
      elsif input.kind_of? String
        OpenSSL::X509::Certificate.new File.read(input)
      else
        raise ArgumentError, "Invalid certificate. Provide a string (file path)" \
          " or an OpenSSL::X509::Certificate instance. Got a #{input.class} instead."
      end
    end

    class Partner < Struct.new :name, :url, :certificate, :tls_verify_mode, :mdn_format, :outbound_format
      def url=(url)
        if url.kind_of? String
          self['url'] = URI.parse url
        else
          self['url'] = url
        end
      end

      def mdn_format=(format)
        format_s = format.to_s
        valid_formats = As2::Server.valid_mdn_formats
        if !valid_formats.include?(format_s)
          raise ArgumentError, "mdn_format '#{format_s}' must be one of #{valid_formats.inspect}"
        end
        self['mdn_format'] = format_s
      end

      def outbound_format=(format)
        format_s = format.to_s
        valid_formats = As2::Client.valid_outbound_formats
        if !valid_formats.include?(format_s)
          raise ArgumentError, "outbound_format '#{format_s}' must be one of #{valid_formats.inspect}"
        end
        self['outbound_format'] = format_s
      end

      def certificate=(certificate)
        self['certificate'] = As2::Config.build_certificate(certificate)
      end

      # if set, will be used for SSL transmissions.
      # @see `verify_mode` in https://ruby-doc.org/stdlib-2.7.1/libdoc/net/http/rdoc/Net/HTTP.html
      def tls_verify_mode=(mode)
        valid_modes = [nil, OpenSSL::SSL::VERIFY_NONE, OpenSSL::SSL::VERIFY_PEER]
        if !valid_modes.include?(mode)
          raise ArgumentError, "tls_verify_mode '#{mode}' must be one of #{valid_modes.inspect}"
        end

        self['tls_verify_mode'] = mode
      end
    end

    class ServerInfo < Struct.new :name, :url, :certificate, :pkey, :domain
      def url=(url)
        if url.kind_of? String
          self['url'] = URI.parse url
        else
          self['url'] = url
        end
      end

      def certificate=(certificate)
        self['certificate'] = As2::Config.build_certificate(certificate)
      end

      def pkey=(input)
        # looks like even though you OpenSSL::PKey.new, you still end up with
        # an instance which is an OpenSSL::PKey::PKey.
        if input.kind_of? OpenSSL::PKey::PKey
          self['pkey'] = input
        elsif input.kind_of? String
          self['pkey'] = OpenSSL::PKey.read File.read(input)
        else
          raise ArgumentError, "Invalid private key. Provide a string (file path)" \
            " or an OpenSSL::PKey instance. Got a #{input.class} instead."
        end
      end

      def add_partner
        partner = Partner.new
        yield partner
        unless partner.name
          raise 'Partner name is required'
        end
        unless partner.certificate
          raise 'Partner certificate is required'
        end
        unless partner.url
          raise 'Partner URL is required'
        end
        Config.partners[partner.name] = partner
        Config.store.add_cert partner.certificate
      end
    end

    class << self
      attr_reader :server_info

      def configure
        @server_info ||= ServerInfo.new
        yield @server_info
        unless @server_info.name
          raise 'Your Partner name is required'
        end
        unless @server_info.certificate
          raise 'Your certificate is required'
        end
        unless @server_info.url
          raise 'Your URL is required'
        end
        unless @server_info.domain
          raise 'Your domain name is required'
        end
        store.add_cert @server_info.certificate
      end

      def partners
        @partners ||= {}
      end

      def store
        @store ||= OpenSSL::X509::Store.new
      end

      def reset!
        @partners = {}
        @store = OpenSSL::X509::Store.new
      end
    end
  end
end
