require 'openssl'
require 'mail'
require 'as2/config'
require 'as2/server'
require 'as2/client'
require 'as2/digest_selector'
require "as2/version"

module As2
  def self.configure(&block)
    Config.configure(&block)
  end

  def self.reset_config!
    Config.reset!
  end
end
