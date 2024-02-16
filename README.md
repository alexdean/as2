# As2

This is a proof of concept implementation of AS2 protocol: http://www.ietf.org/rfc/rfc4130.txt.

Tested with the mendelson AS2 implementation from http://as2.mendelson-e-c.com
and with [OpenAS2](https://github.com/OpenAS2/OpenAs2App).

## Build Status

[![Test Suite](https://github.com/alexdean/as2/actions/workflows/test.yml/badge.svg)](https://github.com/alexdean/as2/actions/workflows/test.yml)

## Known Limitations

These limitations may be removed over time as demand (and pull requests!) come
along.

RFC defines a number of optional features that partners can pick and choose
amongst. We currently have hard-coded options for many of these. Our current
choices are likely the most common ones in use, but we do not offer all the
configuration options needed for a fully-compliant implementation.

https://datatracker.ietf.org/doc/html/rfc4130#section-2.4.2


  1. Encrypted or Unencrypted Data: We assume all messages are encrypted. An
    error will result if partner sends us an unencrypted message.
  2. Signed or Unsigned Data: We error if partner sends an unsigned message.
    Partners can request unsigned MDNs, but we always send signed MDNs.
  3. Optional Use of Receipt: We always send a receipt.
  4. Use of Synchronous or Asynchronous Receipts: We do not support asynchronous
    delivery of MDNs.
  5. Security Formatting: We should be reasonably compliant here.
  6. Hash Function, Message Digest Choices: We currently always use sha256 for
    signing. Since [#20](https://github.com/alexdean/as2/pull/20) we have supported
    allowing partners to request which algorithm we use for MIC generation in MDNs.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'as2'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install as2

## Configuration

Configuration objects need to be initialized for the local system and once for each partner.

See scripts in `examples` directory for more usage info.

A a certificate can be specified as either:

  * a string path to a file containing a PEM-encoded X509 certificate
  * or an instance of `OpenSSL::X509::Certificate`

A private key can be specified as either:

  * a string path to a file containing a PEM-encoded private key
  * or an instance of `OpenSSL::PKey::PKey`

### Local System

Supported options:

  * `name`: AS2 id for the local system. (Used as `As2-From` in outbound messages.)
  * `url`: URL of this system. Mainly for informational purposes.
  * `domain`: DNS domain name of this system. Mainly for informational purposes.
  * `certificate`: Certificate used for signing outbound messages.
  * `pkey`: Private key used for decrypting incoming messages.

### Partners

Supported options:

  * `name`: AS2 id for this partner. (Used as `As2-To` in outbound messages.)
  * `url`: URL to POST outbound messages to.
  * `certificate`: Certificate to use for both encryption and signature verification.
    * If this is specified, it will be used for both `encryption_certificate` and `signing_certificate`.
  * `encryption_certificate`: Certificate to use for encrypting outbound messages.
    * Only required if `certificate` is not set.
  * `signing_certificate`: Certificate to use when verifying signatures on incoming messages.
    * Only required if `certificate` is not set.
  * `encryption_cipher`: Cipher to use when encrypting outbound messages. A default value is used if this is not specified.
    * Call `As2::Client.valid_encryption_ciphers` for valid options.
  * `tls_verify_mode`: Optional. Set to `OpenSSL::SSL::VERIFY_NONE` if partner is using a self-signed certificate for HTTPS.
  * `mdn_format`: Format to use when building MDNs to send to partners.
    * `v0`: older/original format which is less compatible with other AS2 systems, but is the default for backwards-compatibility reasons.
    * `v1`: improved format with better compatibility with other AS2 systems.
  * `outbound_format`: Format to use when building outbound messages.
    * `v0`: older/original format which is less compatible with other AS2 systems, but is the default for backwards-compatibility reasons.
    * `v1`: improved format with better compatibility with other AS2 systems.
  * `base64_scheme`: What type of base64 encoding to perform on outbound message bodies.
    * `rfc4648`: older/original format which is less compatible with other AS2 systems, but is the default for backwards-compatibility reasons.
    * `rfc2045`: format understood by more AS2 systems & recommended for new integrations.

### Example

```ruby
As2.configure do |conf|
  conf.name = 'RUBYAS2'
  conf.url = 'http://localhost:3000/as2'
  conf.certificate = 'test/certificates/server.crt'
  conf.pkey = 'test/certificates/server.key'
  conf.domain = 'localhost'

  conf.add_partner do |partner|
    partner.name = 'MENDELSON'
    partner.url = 'http://localhost:8080/as2/HttpReceiver'
    partner.certificate = 'test/certificates/client.crt'
    partner.outbound_format = 'v1'
    partner.mdn_format = 'v1'
    partner.base64_scheme = 'rfc2045'
  end

  conf.add_partner do |partner|
    partner.name = 'OPENAS2'
    partner.url = 'http://localhost:4088'
    partner.certificate = 'test/certificates/client.crt'
    partner.outbound_format = 'v1'
    partner.mdn_format = 'v1'
    partner.base64_scheme = 'rfc2045'
  end
end
```

## Usage

Generate self signed server certificate:

### One step

`openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365`

### Multi step

1. Generate a key ` openssl genrsa -des3 -out server.key 1024 `
2. Copy the protected key ` cp server.key server.key.org `
3. Remove the passphrase ` openssl rsa -in server.key.org -out server.key `
4. Generate signing request ` openssl req -new -key server.key -out server.csr `
5. Sign the request with your key ` openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt `

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

You can run a local server with `bundle exec ruby examples/server.rb` and send it a file with `bundle exec ruby examples/client.rb <file>`. You may need to generate new certificates under `test/certificates` first (using `localhost` as your common name).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/alexdean/as2.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

## Acknowledgments

Original implementation by:
- [andruby](https://github.com/andruby)
- [datanoise](https://github.com/datanoise)
