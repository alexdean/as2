source 'https://rubygems.org'

# Specify your gem's dependencies in as2.gemspec
gemspec

# from https://github.com/rails/rails/pull/42308/files
if RUBY_VERSION >= "3.1"
  # net-smtp, net-imap and net-pop were removed from default gems in Ruby 3.1, but is used by the `mail` gem.
  # So we need to add them as dependencies until `mail` is fixed: https://github.com/mikel/mail/pull/1439
  gem "net-smtp", require: false
  gem "net-imap", require: false
  gem "net-pop", require: false
end
