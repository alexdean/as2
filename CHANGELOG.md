## Unreleased

  * Improve example server to make it more useful for local testing & development. [#17](https://github.com/alexdean/as2/pull/17)
  * Server can examine HTTP headers to determine desired MIC algorithm and respond accordingly.

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
