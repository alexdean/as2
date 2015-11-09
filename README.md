# As2

This is a proof of concept implementation of AS2 protocol: http://www.ietf.org/rfc/rfc4130.txt.

Tested with the mendelson AS2 implementation from http://as2.mendelson-e-c.com

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

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/as2.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
