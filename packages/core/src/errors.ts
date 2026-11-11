/** Reason codes from proposal 7.4. Server codes go on the wire; client codes stay local. */
export type ServerErrorReason =
  | 'response_encryption_extension_missing'
  | 'response_encryption_unsupported_version'
  | 'response_encryption_unknown_key_id'
  | 'response_encryption_invalid_ephemeral_key'
  | 'response_encryption_invalid_url'
  | 'response_encryption_nonce_mismatch'
  | 'response_encryption_encryption_failed';

export type ClientErrorReason =
  | 'response_encryption_unsupported_version'
  | 'response_encryption_unsupported_suite'
  | 'response_encryption_invalid_public_key'
  | 'response_encryption_key_id_mismatch'
  | 'response_encryption_attestation_invalid'
  | 'response_encryption_attestation_expired'
  | 'response_encryption_pay_to_mismatch'
  | 'response_encryption_resource_url_mismatch'
  | 'response_encryption_decrypt_failed';

export type UrlErrorReason =
  | 'url_not_absolute'
  | 'url_unsupported_scheme'
  | 'url_userinfo_not_allowed'
  | 'url_non_ascii_host'
  | 'url_invalid_authority'
  | 'url_invalid_port'
  | 'url_encoded_dot_segment'
  | 'url_invalid_percent_encoding';

export type ErrorReason = ServerErrorReason | ClientErrorReason | UrlErrorReason;

export class ResponseEncryptionError extends Error {
  constructor(
    readonly reason: ErrorReason,
    message?: string,
  ) {
    super(message ?? reason);
    this.name = 'ResponseEncryptionError';
  }
}
