## 0.10.0 September 13, 2023

support for separate signing & encryption certificates for partners. [#34](https://github.com/alexdean/as2/pull/34)

BREAKING CHANGES:

  * `As2::Config::Partner`
    * Added `signing_certificate` and `encryption_certificate`
    * Removed `certificate`.
    * `certificate=` is still supported, and assigns the same certificate to both.
  * `As2::Client#parse_signed_mdn`: requires `signing_certificate:` rather than `certificate:`.
  * `As2::Message.verify`: requires `signing_certificate:` rather than `certificate:`.

## 0.9.0, August 28, 2023

  * Bugfix for quoting AS2-From/AS2-To identifiers
  * Add utility method for un-quoting identifiers

both implemented in [#33](https://github.com/alexdean/as2/pull/33)

## 0.8.0, August 25, 2023

  * Quote AS2-From/AS2-To identifiers which contain spaces. [#30](https://github.com/alexdean/as2/pull/30)
  * Small improvements to aid integration testing with partners. [#31](https://github.com/alexdean/as2/pull/31)

## 0.7.0, August 25, 2023

Two improvements in compatibility with IBM Sterling, which could not understand
our existing message & MDN formats.

These changes are opt-in only, and require a config change to use. See linked PRs for
details.

  * Improved formatting of MDN messages. [#25](https://github.com/alexdean/as2/pull/25)
  * Improved formatting of outbound messages. [#28](https://github.com/alexdean/as2/pull/28)

## 0.6.0, April 4, 2023

  * allow verification of signed MDNs which use `Content-Transfer-Encoding: binary`. [#22](https://github.com/alexdean/as2/pull/22)
  * Improve example server to make it more useful for local testing & development. [#17](https://github.com/alexdean/as2/pull/17)
  * Support `Content-Tranfer-Encoding: binary`. [#11](https://github.com/alexdean/as2/pull/11)
  * Server can choose MIC algorithm based on HTTP `Disposition-Notification-Options` header. [#20](https://github.com/alexdean/as2/pull/20)

## 0.5.1, August 10, 2022

  * Any HTTP 2xx status received from a partner should be considered successful. [#12](https://github.com/andjosh/as2/pull/12)

## 0.5.0, March 21, 2022

  * improvements to `As2::Client`. improve compatibility with non-Mendelson AS2 servers. [#8](https://github.com/andjosh/as2/pull/8)
  * improve MDN generation, especially when an error occurs. [#9](https://github.com/andjosh/as2/pull/9)
  * successfully parse unsigned MDNs. [#10](https://github.com/andjosh/as2/pull/10)

## 0.4.0, March 3, 2022

  * client: correct MIC & signature verification when processing MDN response [#7](https://github.com/andjosh/as2/pull/7)
    * also improves detection of successful & unsuccessful transmissions.
  * client can transmit content which is not in a local file [#5](https://github.com/andjosh/as2/pull/5)
    * also enables `As2::Client` and `As2::Server` can be used without reference to
      the `As2::Config` global configuration.
    * This allows certificate selection to be determined at runtime, making certificate
      expiration & changeover much easier to orchestrate.

## 0.3.0, Dec 22, 2021

  * fix MIC calculation. [#1](https://github.com/andjosh/as2/pull/1)
  * allow loading of private key and certificates without local files. [#2](https://github.com/andjosh/as2/pull/2)
  * fix signature verification. [#3](https://github.com/andjosh/as2/pull/3)

### breaking changes

  * removed `As2::Message#original_message`
  * removed `As2::Server::HEADER_MAP`

## prior to 0.3.0

Initial work by [@andjosh](https://github.com/andjosh) and [@datanoise](https://github.com/datanoise).
