# Adscore GO Common

[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)

This library provides various utilities for parsing [Adscore](https://adscore.com) signatures,
generating custom request payloads, and virtually anything that might be useful for customers doing server-side
integration with the service.

## Compatibility

### Supported Signature v5 algorithms

1. `v5_0200H - OpenSSL CBC, HTTP query`
2. `v5_0201H - OpenSSL GCM, HTTP query`
3. `v5_0200J - OpenSSL CBC, JSON`
4. `v5_0201J - OpenSSL GCM, JSON`

### Not supported Signature v5 algorithms

1. `v5_0101I - sodium secretbox, igbinary`
2. `v5_0200I - OpenSSL CBC, igbinary`
3. `v5_0201I - OpenSSL GCM, igbinary`
5. `v5_0101H - sodium secretbox, HTTP query`
6. `v5_0101S - sodium secretbox, PHP serialize`
7. `v5_0101J - sodium secretbox, JSON`
8. `v5_0101M - sodium secretbox, msgpack`
9. `v5_0200M - OpenSSL CBC, msgpack`
10. `v5_0201M - OpenSSL GCM, msgpack`
11. `v5_0200S - OpenSSL CBC, PHP serialize`
12. `v5_0201S - OpenSSL GCM, PHP serialize`

## Install

Requires GO >= v1.22.5

## Usage

### V4 signature decryption

When zone's "Response signature algorithm" is set to "Hashing" or "Signing", it means that V4 signatures are in use.
They provide basic means to check incoming traffic for being organic and valuable, but do not carry any additional
information.

```go
package main

import (
	judge "github.com/Adscore/go-common/judge"
	adscoreSignature "github.com/Adscore/go-common/signature"
	adscoreErrors "github.com/Adscore/go-common/adscoreErrors"
)

func main() {

	/*  Replace <key> with "Zone Response Key" which you might find in "Zone Encryption" page for given zone.
	    Those keys are base64-encoded and the library expects raw binary, so we need to decode it now. */
	cryptKey := "<key>"

	/*  Three things are necessary to verify the signature - at least one IP address, User Agent string
	    and the signature itself. */
	var signature string = request.Body

	var userAgent string = request.Header.Get("User-Agent")

	/*  You might want to use X-Forwarded-For or other IP-forwarding headers coming from for example load
	    balancing services, but make sure you trust them and they are not vulnerable to user modification! */
	ipAddresses := []string{request.RemoteAddr}

	obj, err := adscoreSignature.CreateSignatureV4FromRequest(signature, ipAddresses, userAgent, cryptKey)

	if err != nil {
		switch err.(type) {
		case *adscoreErrors.VersionError:
			/*  It means that the signature is not the V4 one, check your zone settings and ensure the signatures
			    are coming from the chosen zone. */
		case *adscoreErrors.ParseError:
			/*  It means that the signature metadata is malformed and cannot be parsed, or contains invalid data,
			    check for corruption underway. */
		case *adscoreErrors.VerifyError:
			/*  Signature could not be verified - usually this is a matter of IP / user agent mismatch (or spoofing).
            They must be bit-exact, so even excessive whitespace or casing change can trigger the problem. */
		}
	}

	/*  Result contains numerical result value */
	result := obj.Result

	/*  Judge is the module evaluating final result in the form of single score. RESULTS constant
            contains array with human-readable descriptions of every numerical result, if needed. */
	humanReadable := judge.Judge[obj.Result]
	humanReadableResult := judge.RESULTS[result].Name + " (" + judge.RESULTS[result].Verdict + ")"
}
```

### V5 signature decryption

V5 is in fact an encrypted payload containing various metadata about the traffic. Its decryption does not rely on IP
address nor User Agent string, so it is immune for environment changes usually preventing V4 to be even decoded.
Judge result is also included in the payload, but client doing the integration can make its own decision basing on
the metadata accompanying.

The format supports a wide variety of encryption and serialization methods, some
of them are included in this repository, but it can be extended to fulfill specific needs.

It can be integrated in V4-compatible mode, not making use of any V5 features (see V4 verification):

```go
package main

import (
	"encoding/base64"

	judge "github.com/Adscore/go-common/judge"
	adscoreSignature "github.com/Adscore/go-common/signature"
	adscoreErrors "github.com/Adscore/go-common/adscoreErrors"
)

func main() {

	/*  Replace <key> with "Zone Response Key" which you might find in "Zone Encryption" page for given zone.
    Those keys are base64-encoded and the library expects raw binary, so we need to decode it now. */
	cryptKey, err := base64.StdEncoding.DecodeString("<key>")

	/*  Three things are necessary to verify the signature - at least one IP address, User Agent string
        and the signature itself. */
	var signature string = request.Body

	var userAgent string = request.Header.Get("User-Agent")

	/*  You might want to use X-Forwarded-For or other IP-forwarding headers coming from for example load
        balancing services, but make sure you trust them and they are not vulnerable to user modification! */
	ipAddresses := []string{request.RemoteAddr}

	obj, err := adscoreSignature.CreateSignatureV5FromRequest(signature, ipAddresses, userAgent, cryptKey)

	if err != nil {
		switch err.(type) {
		case *adscoreErrors.VersionError:
			/*  It means that the signature is not the V5 one, check your zone settings and ensure the signatures
        are coming from the chosen zone. */
		case *adscoreErrors.ParseError:
			/*  It means that the signature metadata is malformed and cannot be parsed, or contains invalid data,
        check for corruption underway. */
		case *adscoreErrors.VerifyError:
			/*  Signature could not be verified - see error message for details. */
		}
	}

	result := obj.Result
	humanReadable := judge.Judge[obj.Result]
	humanReadableResult := judge.RESULTS[result].Name + " ("  + judge.RESULTS[result].Verdict + ")"
}
```

`adscoreSignature.GetZoneId()` can be used in scenarios, where signatures coming from different zones are handled at
a single point. This is not possible for V4 signatures, as they do not carry over any zone information.

As we can see, `CreateSignatureV5FromRequest` also requires a list of IP addresses and User Agent string. This is used for
built-in verification routine, but this time the verification is completely unrelated to decryption. Client integrating
might want to replace the verification with its own implementation, so here is the extended example (without any
exception handling for readability):

```go
package main

import (
	judge "github.com/Adscore/go-common/judge"
	adscoreSignature "github.com/Adscore/go-common/signature"
)

func main() {
	/*  Three things are necessary to verify the signature - at least one IP address, User Agent string
	    and the signature itself. */
	var signature string = request.Body

	var userAgent string = request.Header.Get("User-Agent")

	/*  You might want to use X-Forwarded-For or other IP-forwarding headers coming from for example load
	    balancing services, but make sure you trust them and they are not vulnerable to user modification! */
	ipAddresses := []string{request.RemoteAddr}

	format := "BASE64_VARIANT_URLSAFE_NO_PADDING"

	zoneId, err := adscoreSignature.GetZoneId(signature, format)

	// You'll need to implement the getCryptKeyByZoneId function yourself to obtain the crypt key using the Zone ID
	cryptKey := getCryptKeyByZoneId(zoneId)

	obj := &adscoreSignature.Signature5{}

	err = obj.Parse(signature, cryptKey, format)

	err = obj.Verify(ipAddresses, userAgent)

	result := obj.Result
	humanReadable := judge.Judge[obj.Result]
	humanReadableResult := judge.RESULTS[result].Name + " (" + judge.RESULTS[result].Verdict + ")"
}
```

The `Result` field return result score only after a successful `verify()` call.
This is expected behavior, to preserve compliance with V4 behavior - the result is only valid when it's proven
belonging to a visitor.
For custom integrations not relying on built-in verification routines (usually more tolerant), the result is present
also in payload retrieved via `Payload` field, but it's then the integrator's responsibility to ensure whether
it's trusted or not. When desired validation is more strict than the built-in one, the `verify()` can be called first,
populating `Result` value, and after that any additional verification may take place.

Note: V4 signature parser also holds the payload, but it does not contain any useful information, only timestamps and
signed strings; especially - it does not contain any Judge result value, it is derived from the signature via several
hashing/verification approaches.

## Integration

Any questions you have with custom integration, please contact our support@adscore.com. Please remember that we do
require adequate technical knowledge in order to be able to help with the integration; there are other integration
methods which do not require any, or require very little programming.
