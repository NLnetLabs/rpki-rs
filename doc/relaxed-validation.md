# Relaxed RPKI Validation

The documents defining RPKI include a number of very strict rules
regarding the formatting of the objects published in the RPKI repository.
However, because PRKI reuses existing technology, real-world applications
produce objects that do not follow these strict requirements.

As a consequence, a significant portion of the RPKI repository is actually
invalid if the rules are followed. We therefore introduce two validation
modes: strict and relaxed. Strict mode rejects any object that does not
pass all checks laid out by the relevant RFCs. Relaxed mode ignores a
number of these checks.

This memo documents the violations we encountered and are dealing with in
relaxed validation mode.


## Resource Certificates (RFC 6487)

Resource certificates are defined as a profile on the more general
Internet PKI certificates defined in RFC 5280.


### Subject and Issuer

The RFC restricts the type used for CommonName attributes to
PrintableString, allowing only a subset of ASCII characters, while RFC
5280 allows a number of additional string types. At least one CA produces
resource certificates with Utf8Strings.

In relaxed mode, we will only check that the general structure of the
issuer and subject fields are correct and allow any number and types of
attributes. This seems justified since RPKI explicitly does not use these
fields.


### Subject Information Access

RFC 6487 forbids any access methods other than id-ad-signedObject for EE
certificates. However, there is CAs that also the id-ad-rpkiNotify method
for RRDP to these certificates which are declared for certificate
authority use by RFC 81821.

In relaxed mode, we tolerate id-ad-rpkiNotify access methods in EE
certificates.


## Signed Objects (RFC 6488)

Signed objects are defined as a profile on CMS messages defined in RFC
5652.


### DER Encoding

RFC 6488 demands all signed objects to be DER encoded while the more
general CMS format allows any BER encoding – DER is a stricter subset of
the more general BER. At least one CA does indeed produce BER encoded
signed objects.

In relaxed mode, we will allow BER encoding.

Note that this isn’t just nit-picking. In BER encoding, octet strings can
be broken up into a sequence of sub-strings. Since those strings are in
some places used to carry encoded content themselves, such an encoding
does make parsing significantly more difficult. At least one CA does
produce such broken-up strings.

