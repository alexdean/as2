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

    class Partner < Struct.new :name, :url, :encryption_certificate, :encryption_cipher, :signing_certificate, :tls_verify_mode, :mdn_format, :outbound_format, :base64_scheme
      def initialize
        # set default.
        self.encryption_cipher = 'aes-256-cbc'
        self.base64_scheme = 'rfc4648'
      end

      def base64_scheme=(scheme)
        scheme_s = scheme.to_s
        valid_schemes = As2.valid_base64_schemes
        if !valid_schemes.include?(scheme_s)
          raise ArgumentError, "base64_scheme '#{scheme_s}' must be one of #{valid_schemes.inspect}"
        end
        self['base64_scheme'] = scheme_s
      end

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
        cert = As2::Config.build_certificate(certificate)
        self['encryption_certificate'] = cert
        self['signing_certificate'] = cert
      end

      def encryption_certificate=(certificate)
        self['encryption_certificate'] = As2::Config.build_certificate(certificate)
      end

      def encryption_cipher=(cipher)
        cipher_s = cipher.to_s
        valid_ciphers = As2::Client.valid_encryption_ciphers
        if !valid_ciphers.include?(cipher_s)
          raise ArgumentError, "encryption_cipher '#{cipher_s}' must be one of #{valid_ciphers.inspect}"
        end
        self['encryption_cipher'] = cipher_s
      end

      def encryption_cipher_instance
        OpenSSL::Cipher.new(encryption_cipher)
      end

      def signing_certificate=(certificate)
        self['signing_certificate'] = As2::Config.build_certificate(certificate)
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
        unless partner.signing_certificate
          raise 'Partner signing certificate is required'
        end
        unless partner.encryption_certificate
          raise 'Partner encryption certificate is required'
        end
        unless partner.url
          raise 'Partner URL is required'
        end
        Config.partners[partner.name] = partner
        Config.store.add_cert partner.signing_certificate
        Config.store.add_cert partner.encryption_certificate
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

      # TODO: deprecate this.
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
