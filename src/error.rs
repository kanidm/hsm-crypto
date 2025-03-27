#[derive(Debug, Clone)]
pub enum TpmError {
    AuthValueInvalidHexInput,
    AuthValueTooShort,
    AuthValueDerivation,

    Aes256GcmEncrypt,
    Aes256GcmDecrypt,
    Aes256KeyInvalid,
    // Aes256GcmConfig,
    AsnBitStringInvalid,
    // HmacKey,
    // HmacSign,
    HmacKeyInvalid,
    // EcGroup,
    // EcKeyGenerate,
    // EcKeyPrivateToDer,
    // EcKeyFromDer,
    EcKeyToPrivateKey,
    // EcdsaPublicFromComponents,
    EcdsaPublicToDer,
    EcdsaPublicToPem,
    EcdsaSignature,
    // IdentityKeyDigest,
    // IdentityKeyPublicToDer,
    // IdentityKeyPublicToPem,
    // IdentityKeyInvalidForSigning,
    // IdentityKeyInvalidForVerification,
    // IdentityKeySignature,
    // IdentityKeyVerification,
    // IdentityKeyX509ToPem,
    // IdentityKeyX509ToDer,
    // IdentityKeyX509Missing,
    RsaGenerate,
    RsaPrivateToDer,
    RsaPrivateFromDer,
    RsaPublicToDer,
    RsaPublicToPem,
    RsaPkcs115Sign,
    RsaOaepEncrypt,
    RsaOaepDecrypt,
    // RsaToPrivateKey,
    // RsaPublicFromComponents,

    // X509FromDer,
    // X509PublicKey,
    // X509KeyMismatch,
    // X509RequestBuilder,
    // X509NameBuilder,
    // X509NameAppend,
    // X509RequestSubjectName,
    // X509RequestSign,
    // X509RequestToDer,
    // X509RequestSetPublic,

    // MsOapxbcKeyPublicToDer,
    // MsOapxbcKeyOaepOption,
    // MsOapxbcKeyOaepDecipher,
    // MsOapxbcKeyOaepEncipher,
    TssTctiNameInvalid,
    TssAuthSession,
    TssContextCreate,
    TssContextFlushObject,
    TssContextSave,
    TssContextLoad,
    TssPrimaryObjectAttributesInvalid,
    TssPrimaryPublicBuilderInvalid,
    TssPrimaryCreate,
    TssEntropy,
    TssAuthValueInvalid,

    // TpmMachineKeyObjectAttributesInvalid,
    // TpmMachineKeyBuilderInvalid,
    TssStorageKeyCreate,
    TssStorageKeyLoad,
    TssKeyLoad,

    // TpmMsRsaKeyLoad,
    // TpmHmacKeyLoad,
    TssStorageKeyObjectAttributesInvalid,
    TssStorageKeyBuilderInvalid,

    TssHmacKeyObjectAttributesInvalid,
    TssHmacKeyBuilderInvalid,
    TssHmacKeyCreate,
    TssHmacSign,
    TssHmacInputTooLarge,
    TssHmacOutputInvalid,

    TssEs256KeyCreate,
    TssEs256PublicCoordinatesInvalid,
    TssEs256SignatureCoordinatesInvalid,
    TssRs256KeyCreate,
    TssRs256SignatureInvalid,
    TpmRs256OaepInvalidInputLength,
    TssRs256OaepDecrypt,
    TssRs256UnsealNotSupported,
    TssRsaPublicFromComponents,
    TssKeyObjectAttributesInvalid,
    TssKeyAlgorithmInvalid,
    TssKeyBuilderInvalid,
    TssKeyReadPublic,
    TssInvalidSignature,
    TssKeySign,
    TssKeyDigest,
    TssSealingKeyLoad,
    TssSealDataTooLarge,
    TssSeal,
    TssUnseal,

    // TpmIdentityKeyCreate,
    // TpmIdentityKeySign,
    // TpmIdentityKeyId,
    // TpmIdentityKeySignatureInvalid,
    // TpmIdentityKeyEcdsaSigRInvalid,
    // TpmIdentityKeyEcdsaSigSInvalid,
    // TpmIdentityKeyEcdsaSigFromParams,
    // TpmIdentityKeyEcdsaSigToDer,

    // TpmIdentityKeyParamInvalid,
    // TpmIdentityKeyParamsToRsaSig,

    // TpmIdentityKeyDerToEcdsaSig,
    // TpmIdentityKeyParamRInvalid,
    // TpmIdentityKeyParamSInvalid,
    // TpmIdentityKeyParamsToEcdsaSig,
    // TpmIdentityKeyVerify,

    // TpmMsRsaKeyObjectAttributesInvalid,
    // TpmMsRsaKeyAlgorithmInvalid,
    // TpmMsRsaKeyBuilderInvalid,
    // TpmMsRsaKeyCreate,
    // TpmMsRsaKeyReadPublic,
    // TpmMsRsaOaepDecrypt,
    // TpmMsRsaOaepInvalidKeyLength,
    // TpmMsRsaSeal,
    // TpmMsRsaUnseal,

    // TpmOperationUnsupported,

    // Entropy,
    IncorrectKeyType,
}
