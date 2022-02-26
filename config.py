
# tests we don't emit rust code for.
skip_tests = set([
    # appears to be broken in x509test; build process makes empty file.
    'ok_ca',
])

# tests that want to validate parsing/processing of cA=true certificates
tests_apply_to_anchor = dict(

    # FIXME: test against trust anchor parsing

    # XXX: missing name constraints validation:
    # - iPAddress should be 8 octets
    # - should be non-empty
    # - should be marked critical
    # - must either process minimum/maximum or reject
    # xf_ext_name_constraints_badip = 'BadDER',
    # xf_ext_name_constraints_empty = 'BadDER',
    # xf_ext_name_constraints_noncrit = 'BadDER',
    # xf_ext_name_constraints_minmax = 'BadDER',

    # XXX: cA=true without subjectKeyIdentifier should be rejected
    # xf_ext_subject_keyid_ca_absent = '',
)

# expected errors for ok- tests (ie, chains that are theoretically
# valid according to the standard -- but are rejected by webpki)
error_for_ok_test = dict(
    # v1/v2 certificates not supported
    ok_v1 = 'UnsupportedCertVersion',
    ok_v2 = 'UnsupportedCertVersion',
    ok_v2_issuer_asn1_differ = 'UnsupportedCertVersion',

    # basic constraints with CA=true as end-entity
    ok_ext_basic_constraints = 'CaUsedAsEndEntity',
    ok_ext_name_constraints = 'CaUsedAsEndEntity',

    # inhibitAnyPolicy not supported
    ok_ext_inhibit_anypolicy = 'UnsupportedCriticalExtension',

    # times before 1970 outlawed
    ok_utc_time_wrap = 'BadDERTime',

    # DSA not supported
    ok_inherited_keyparams = 'UnknownIssuer',

    # policyMappings not supported
    ok_ext_policy_map = 'UnsupportedCriticalExtension',

    # XXX: appears to do bytewise comparison of encoding rather than RFC4518
    ok_issuer_asn1_differ = 'UnknownIssuer',

    # XXX: subjectUniqueID (context[2]) not skipped when expecting extensions (context[3])
    ok_uniqueid_incomplete_byte = 'MissingOrMalformedExtensions',

    # XXX: support is a RFC5280 'MUST'
    ok_ext_policy_constraints = 'UnsupportedCriticalExtension',
)

error_for_xf_test = dict(
    xf_algo_mismatch1 = 'SignatureAlgorithmMismatch',
    xf_der_invalid_bitstring = 'MissingOrMalformedExtensions',
    xf_der_invalid_nonminimal_int = 'BadDER',
    xf_der_invalid_uniqueid = 'MissingOrMalformedExtensions',

    xf_ext_constraints_neg_pathlen = 'BadDER',

    # OK: we allow basicConstraints on non-CA certs, which means the clause
    # requiring it to be critical on CA certs does not apply.
    # xf_ext_constraints_noncritical = '',
    #
    # OK: same goes for these too.
    # xf_ext_constraints_path_nonca = '',
    # xf_ext_constraints_path_nosign = '',

    # XXX: not rejected as expected
    # xf_der_pubkey_rsa_nonminimal_int = 'BadDER',

    # XXX: two identical authorityKeyIdentifier extensions not rejected
    # xf_duplicate_extension = 'ExtensionValueInvalid',

    # XXX: two different keyUsage extensions not rejected (as they're ignored)
    # xf_duplicate_extension2 = 'ExtensionValueInvalid',

    # XXX: subjectAltName of " " not rejected
    # xf_ext_altname_blank_domain = 'BadDER',

    # OK: subjectAltName marked critical, but we don't support subject
    # xf_ext_altname_critical_subject = '',

    # OK: email subjectAltName not supported
    # xf_ext_altname_email_only = '',
    # xf_ext_altname_invalid_email = '',

    # XXX: subjectAltName with zero items
    # xf_ext_altname_empty = '?',

    # XXX: subjectAltName with empty item
    # xf_ext_altname_empty2 = '?',

    xf_ext_altname_invalid_domain = 'BadDER',
    xf_ext_altname_invalid_encoding = 'BadDER',

    # OK: registeredID not supported
    # xf_ext_name_constraints_regid = '',

    # XXX: iPAddress with 5 octets not rejected
    # xf_ext_altname_ip_wrong = 'BadDER',

    # XXX: non-critical sAN not rejected
    # xf_ext_altname_noncrit_nosubj = '?',

    # OK: uniformResourceIdentifier not supported
    # xf_ext_altname_relative_uri = '',
    # xf_ext_altname_schemeless_uri = '',

    xf_ext_auth_info_critical = 'UnsupportedCriticalExtension',
    xf_ext_auth_keyid_critical = 'UnsupportedCriticalExtension',

    # OK: authorityInfoAccess & authorityKeyIdentifier not supported
    # xf_ext_auth_info_empty = '',
    # xf_ext_auth_keyid_invalid_issuer = '',
    # xf_ext_auth_keyid_mismatch = '',
    # xf_ext_auth_keyid_noid = '',
    # xf_ext_auth_keyid_onlyserial = '',
    # xf_ext_auth_keyid_serial_mismatch = '',

    # OK: certificatePolicies not supported
    # xf_ext_cert_policies_any_qual = '',
    # xf_ext_cert_policies_bmp_unotice = '',
    # xf_ext_cert_policies_dup = '',
    # xf_ext_cert_policies_unotice_ch = '',


    xf_ext_crl_point_critical = 'UnsupportedCriticalExtension',

    # OK: cRLDistributionPoints not supported
    # xf_ext_crl_point_reasons_only = '',

    xf_ext_ct_poison = 'UnsupportedCriticalExtension',

    # OK: no CT support
    # xf_ext_ct_sct_trailing_data = '',
    # xf_ext_ct_sct_wrong_type = '',

    # XXX: empty OID in eku list
    #f_ext_extended_key_usage_empty_oid = '?',

    xf_ext_extended_any_key_usage = 'UnknownIssuer',
    xf_ext_extended_key_usage_empty = 'BadDER',
    xf_ext_freshest_crl_critical = 'UnsupportedCriticalExtension',

    # OK: inhibitAnyPolicy not implemented
    # xf_ext_inhibit_anypolicy_negative = '',
    # xf_ext_inhibit_anypolicy_noncritical = '',

    xf_ext_issuer_altname_critical = 'UnsupportedCriticalExtension',

    # OK: keyUsage not implemented (nb 'ext' here is 'extension' rather than 'extended')
    # xf_ext_key_usage_empty = '',
    # xf_ext_key_usage_noncritical = '',
    # xf_ext_key_usage_sign_nonca = '',
    # xf_ext_key_usage_too_long = '',
    # xf_ext_key_usage_wrong_der = '',
    # xf_key_usage_nonsign_maybe1 = '',
    # xf_key_usage_nonsign_maybe2 = '',
    # xf_key_usage_nonsign = '',
    # xf_key_usages_empty = '',
    # xf_key_usages_empty2 = '',

    # XXX: keyCertSign not rejected if cA=false
    # xf_ext_keysign_nonca = '?',

    # XXX: nameConstraints not rejected if cA=false
    # xf_ext_name_constraints_nonca = '',

    xf_ext_policy_constraint_empty = 'UnsupportedCriticalExtension',

    # OK: policyConstraints not implemented
    # xf_ext_policy_constraint_noncrit = '',

    # OK: policyMappings not implemented
    # xf_ext_policy_map_noncritical = '',

    xf_ext_policy_map_empty = 'UnsupportedCriticalExtension',
    xf_ext_policy_map_from_any = 'UnsupportedCriticalExtension',
    xf_ext_policy_map_to_any = 'UnsupportedCriticalExtension',
    xf_ext_policy_map_unref = 'UnsupportedCriticalExtension',

    xf_ext_subject_dirattr_critical = 'UnsupportedCriticalExtension',
    xf_ext_subject_info_critical = 'UnsupportedCriticalExtension',
    xf_ext_subject_keyid_critical = 'UnsupportedCriticalExtension',

    # OK: subjectDirectoryAttributes not implemented
    # xf_ext_subject_dirattr_empty = '',

    # OK: subjectInfoAccess not implemented
    # xf_ext_subject_info_empty = '',

    xf_gentime_fraction_secs = 'BadDERTime',
    xf_gentime_no_secs = 'BadDERTime',
    xf_gentime_nonzulu = 'BadDERTime',

    xf_issuer_mismatch_v2 = 'UnsupportedCertVersion',
    xf_issuer_mismatch1 = 'UnknownIssuer',

    # XXX: missing validation of subject keys?
    # xf_pubkey_ecdsa_not_on_curve = '?',
    # xf_pubkey_ecdsa_secp192r1 = '?',
    # xf_pubkey_ecdsa_unknown_curve = '?',
    # xf_pubkey_rsa_exponent_negative = '?',
    # xf_pubkey_rsa_modulus_negative = '?',
    # xf_pubkey_rsa_param_nonnull = '?',

    xf_serial_negative = 'BadDER',
    xf_serial_zero = 'BadDER',

    # XXX: constraint on issuer, not verifier
    # xf_soon_generalized_time = '',

    # OK: we don't look at subject
    # xf_subject_nonprintable = '',
    # xf_subject_t61 = '',

    xf_unknown_critical_ext = 'UnsupportedCriticalExtension',

    xf_ext_altname_excluded = 'UnknownIssuer',
    xf_ext_name_excluded_dn = 'UnknownIssuer',
    xf_ext_name_excluded_dns = 'UnknownIssuer',
    xf_ext_name_excluded_email = 'UnknownIssuer',
    xf_ext_name_excluded_email2 = 'UnknownIssuer',
    xf_ext_name_excluded_ip = 'UnknownIssuer',
    xf_ext_name_excluded_uri = 'UnknownIssuer',
    xf_ext_name_excluded_uri2 = 'UnknownIssuer',
    xf_ext_name_excluded = 'UnknownIssuer',

    xf_nonca_sign_maybe1 = 'UnknownIssuer',
    xf_nonca_sign_maybe2 = 'UnknownIssuer',
    xf_nonca_sign = 'UnknownIssuer',

    xf_ext_key_usage_wrong = 'UnknownIssuer',


    xf_utctime_nonzulu = 'BadDERTime',
    xf_utctime_no_secs = 'BadDERTime',

    xf_v1_extensions = 'UnsupportedCertVersion',
    xf_v1_uniqueid = 'UnsupportedCertVersion',
    xf_v2_extensions = 'UnsupportedCertVersion',
    xf_v3_uniqueid_noexts1 = 'MissingOrMalformedExtensions',
    xf_v3_uniqueid_noexts2 = 'MissingOrMalformedExtensions',
)
