#![cfg(doc)]
//! # The RPKI RFCs.
//!
//! This documentation module contains a list of all IETF RFCs related to
//! the RPKI.
//!
//! ## General
//!
//! * [RFC 6480](https://www.rfc-editor.org/info/rfc6480) “An Infrastructure
//!   to Support Secure Internet Routing”
//! * [RFC 6481](https://www.rfc-editor.org/info/rfc6481) “A Profile for
//!   Resource Certificate Repository Structure”
//! * **[RFC 6487](https://www.rfc-editor.org/info/rfc6487)** “A Profile for
//!   X.509 PKIX Resource Certificates”
//!   * [RFC 9829](https://www.rfc-editor.org/info/rfc9829) “Handling of
//!     Resource Public Key Infrastructure (RPKI) Certificate Revocation
//!     List (CRL) Number Extensions”
//! * **[RFC 6488](https://www.rfc-editor.org/info/rfc6488)** “Signed Object
//!   Template for the Resource Public Key Infrastructure (RPKI)”
//!   * [RFC 9589](https://www.rfc-editor.org/info/rfc6589) “On the Use of
//!     the Cryptographic Message Syntax (CMS) Signing-Time Attribute in
//!     Resource Public Key Infrastructure (RPKI) Signed Objects”
//! * [RFC 6489](https://www.rfc-editor.org/info/rfc6489) “Certification
//!   Authority (CA) Key Rollover in the Resource Public Key Infrastructure
//!   (RPKI)”
//! * [RFC 8360](https://www.rfc-editor.org/info/rfc8360) “Resource Public
//!   Key Infrastructure (RPKI) Validation Reconsidered”
//!   * Allows trimming of overclaimed resources in certificates.
//! * [RFC 6484](https://www.rfc-editor.org/info/rfc6484) “Certificate
//!   Policy (CP) for the Resource Public Key Infrastructure (RPKI)”
//! * [RFC 7318](https://www.rfc-editor.org/info/rfc8360) “Policy Qualifiers
//!   in Resource Public Key Infrastructure (RPKI) Certificates”
//! * [RFC 9255](https://www.rfc-editor.org/info/rfc9255) “The 'I' in RPKI
//!   Does Not Stand for Identity”
//! * [RFC 6485](https://www.rfc-editor.org/info/rfc6485)** “The Profile
//!   for Algorithms and Key Sizes for Use in the Resource Public Key
//!   Infrastructure.”
//!   * **[RFC 7935](https://www.rfc-editor.org/info/rfc8360)** “The Profile
//!     for Algorithms and Key Sizes for Use in the Resource Public Key
//!     Infrastructure”
//! * [RFC 6916](https://www.rfc-editor.org/info/rfc8360) “Algorithm Agility
//!   Procedure for the Resource Public Key Infrastructure (RPKI)”
//! * **[RFC 8182](https://www.rfc-editor.org/info/rfc8182])** “The RPKI
//!   Repository Delta Protocol (RRDP)”
//!   * [RFC 9697](https://www.rfc-editor.org/info/rfc9697) “Detecting RPKI
//!     Repository Delta Protocol (RRDP) Session Desynchronization”
//!   * [RFC 9674](https://www.rfc-editor.org/info/rfc9674) “Same-Origin
//!     Policy for the RPKI Repository Delta Protocol (RRDP)”
//! * [RFC 6490](https://www.rfc-editor.org/info/rfc6490) “Resource Public
//!   Key Infrastructure (RPKI) Trust Anchor Locator”
//!   * [RFC 7730](https://www.rfc-editor.org/info/rfc7730) “Resource
//!     Public Key Infrastructure (RPKI) Trust Anchor Locator”
//!   * **[RFC 8630](https://www.rfc-editor.org/info/rfc8630)** “Resource
//!     Public Key Infrastructure (RPKI) Trust Anchor Locator”
//! * [RFC 6486](https://www.rfc-editor.org/info/rfc6486) “Manifests for
//!   the Resource Public Key Infrastructure (RPKI)”
//!   * **[RFC 9286](https://www.rfc-editor.org/info/rfc9286)** “Manifests
//!     for the Resource Public Key Infrastructure (RPKI)”
//!   * [RFC 9981](https://www.rfc-editor.org/info/rfc9981) “Resource Public
//!     Key Infrastructure (RPKI) Manifest Number Handling”
//! * [RFC 6482](https://www.rfc-editor.org/info/rfc6482) “A Profile for
//!   Route Origin Authorizations (ROAs)”
//!   * **[RFC 9582](https://www.rfc-editor.org/info/rfc9582)** “A Profile
//!     for Route Origin Authorizations (ROAs)”
//!   * [RFC 9319](https://www.rfc-editor.org/info/rfc9319) “The Use of
//!     maxLength in the Resource Public Key Infrastructure (RPKI)”
//!   * [RFC 9455](https://www.rfc-editor.org/info/rfc9455) “Avoiding Route
//!     Origin Authorizations (ROAs) Containing Multiple IP Prefixes”
//! * **[RFC 8209](https://www.rfc-editor.org/info/rfc8209)** “A Profile for
//!   BGPsec Router Certificates, Certificate Revocation Lists, and
//!   Certification Requests”
//! * **[RFC 9323](https://www.rfc-editor.org/info/rfc9323)** “A Profile for
//!   RPKI Signed Checklists (RSCs)”
//! * **[RFC 9691](https://www.rfc-editor.org/info/rfc9691)** “A Profile for
//!   Resource Public Key Infrastructure (RPKI) Trust Anchor Keys (TAKs)”
//! * Historic RFCs
//!   * [RFC 6493](https://www.rfc-editor.org/info/rfc6493) “The Resource
//!     Public Key Infrastructure (RPKI) Ghostbusters Record”
//!
//! ## BGPsec
//!
//! * **[RFC 8205](https://www.rfc-editor.org/info/rfc8205)** “BGPsec Protocol
//!   Specification”
//! * [RFC 8206](https://www.rfc-editor.org/info/rfc8206) “BGPsec
//!   Considerations for Autonomous System (AS) Migration”
//! * [RFC 8207](https://www.rfc-editor.org/info/rfc8207) “BGPsec
//!   Operational Considerations”
//! * [RFC 8208](https://www.rfc-editor.org/info/rfc8208) “BGPsec
//!   Algorithms, Key Formats, and Signature Formats”
//!   * **[RFC 8608](https://www.rfc-editor.org/info/rfc8608)** “BGPsec
//!     Algorithms, Key Formats, and Signature Formats”
//! * [RFC 7353](https://www.rfc-editor.org/info/rfc7353) “Security
//!   Requirements for BGP Path Validation”
//! * [RFC 8634](https://www.rfc-editor.org/info/rfc8634) “BGPsec Router
//!   Certificate Rollover”
//! * [RFC 8635](https://www.rfc-editor.org/info/rfc8635) “Router Keying
//!   for BGPsec”
//!
//! ## RTR
//!
//! * [RFC 6810](https://www.rfc-editor.org/info/rfc6810)** “The Resource
//!   Public Key Infrastructure (RPKI) to Router Protocol”
//! * **[RFC 8210](https://www.rfc-editor.org/info/rfc8210)** “The Resource
//!   Public Key Infrastructure (RPKI) to Router Protocol, Version 1”
//! * [RFC 6945](https://www.rfc-editor.org/info/rfc6945)** “Definitions of
//!   Managed Objects for the Resource Public Key Infrastructure (RPKI) to
//!   Router Protocol”
//!
//! ## SLURM
//!
//! * **[RFC 8416](https://www.rfc-editor.org/info/rfc8416])** “Simplified
//!   Local Internet Number Resource Management with the RPKI (SLURM)”
//!
//! ## Provisioning
//!
//! * **[RFC 8183](https://www.rfc-editor.org/info/rfc8181])** “An
//!   Out-of-Band Setup Protocol for Resource Public Key Infrastructure
//!   (RPKI) Production Services”
//! * **[RFC 6492](https://www.rfc-editor.org/info/rfc6492])** “A Protocol
//!   for Provisioning Resource Certificates”
//! * **[RFC 8181](https://www.rfc-editor.org/info/rfc8181])** “A Publication
//!   Protocol for the Resource Public Key Infrastructure (RPKI)”
//!
//! ## Other
//!
//! * [RFC 6491](https://www.rfc-editor.org/info/rfc6491) “Resource Public
//!   Key Infrastructure (RPKI) Objects Issued by IANA”
//!
//! ## Informational RFCs and Best Current Practice RFCs
//!
//! * [RFC 6483](https://www.rfc-editor.org/info/rfc6483) “Validation of
//!   Route Origination Using the Resource Certificate Public Key
//!   Infrastructure (PKI) and Route Origin Authorizations (ROAs)”
//! * [RFC 6907](https://www.rfc-editor.org/info/rfc6907) “Use Cases and
//!   Interpretations of Resource Public Key Infrastructure (RPKI) Objects
//!   for Issuers and Relying Parties”
//! * [RFC 7115](https://www.rfc-editor.org/info/rfc7115) “Origin Validation
//!   Operation Based on the Resource Public Key Infrastructure (RPKI)”
//! * [RFC 7132](https://www.rfc-editor.org/info/rfc7132) “Threat Model for
//!   BGP Path Security”
//! * [RFC 7382](https://www.rfc-editor.org/info/rfc7382) “Template for a
//!   Certification Practice Statement (CPS) for the Resource PKI (RPKI)”
//! * [RFC 8211](https://www.rfc-editor.org/info/rfc8416) “Adverse Actions by
//!   a Certification Authority (CA) or Repository Manager in the Resource
//!   Public Key Infrastructure (RPKI)”
//! * [RFC 8488](https://www.rfc-editor.org/info/rfc8488) “RIPE NCC's
//!   Implementation of Resource Public Key Infrastructure (RPKI)
//!   Certificate Tree Validation”
//! * [RFC 8897](https://www.rfc-editor.org/info/rfc8897) “Requirements for
//!   Resource Public Key Infrastructure (RPKI) Relying Parties”

