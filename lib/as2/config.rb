require 'openssl'
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

    class Partner < Struct.new :name, :url, :certificate
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
