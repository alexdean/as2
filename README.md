# As2

This is a proof of concept implementation of AS2 protocol: http://www.ietf.org/rfc/rfc4130.txt.

Tested with the mendelson AS2 implementation from http://as2.mendelson-e-c.com
and with [OpenAS2](https://github.com/OpenAS2/OpenAs2App).

## Build Status

[![Test Suite](https://github.com/alexdean/as2/actions/workflows/test.yml/badge.svg)](https://github.com/alexdean/as2/actions/workflows/test.yml)

## Known Limitations

These limitations may be removed over time as demand (and pull requests!) come
along.

  1. RFC defines a number of optional features that partners can pick and choose
     amongst. We currently have hard-coded options for many of these. Our current
     choices are likely the most common ones in use, but we do not offer all the
     configuration options needed for a fully-compliant implementation. https://datatracker.ietf.org/doc/html/rfc4130#section-2.4.2
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
  2. AS2 partners may agree to use separate certificates for data encryption and data signing.
     We do not support separate certificates for these purposes.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'as2'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install as2

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
