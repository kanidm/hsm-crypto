macro_rules! wrap_aes256gcm {
    (
        $wrapping_key: expr,
        $key_to_wrap: expr
    ) => {{
        let nonce = aes256gcm::new_nonce();
        let cipher = Aes256Gcm::new($wrapping_key);

        let associated_data = b"";
        let mut enc_key = $key_to_wrap.clone();

        let tag = cipher
            .encrypt_in_place_detached(&nonce, associated_data, enc_key.as_mut_slice())
            .map_err(|_| TpmError::Aes256GcmEncrypt)?;

        if enc_key.as_slice() == $key_to_wrap.as_slice() {
            // Encryption didn't replace the buffer in place, fail.
            return Err(TpmError::Aes256GcmEncrypt);
        }

        Ok((enc_key, tag, nonce))
    }};
}

pub(crate) use wrap_aes256gcm;

macro_rules! unwrap_aes256gcm {
    (
        $wrapping_key: expr,
        $key_to_unwrap: expr,
        $tag: expr,
        $nonce: expr
    ) => {{
        let cipher = Aes256Gcm::new($wrapping_key);

        let mut key = $key_to_unwrap.clone();

        let associated_data = b"";

        cipher
            .decrypt_in_place_detached($nonce, associated_data, key.as_mut_slice(), $tag)
            .map_err(|_| TpmError::Aes256GcmDecrypt)?;

        if key.as_slice() == $key_to_unwrap.as_slice() {
            // Encryption didn't replace the buffer in place, fail.
            return Err(TpmError::Aes256GcmDecrypt);
        }

        Ok(key)
    }};
}

pub(crate) use unwrap_aes256gcm;

macro_rules! unwrap_aes256gcm_nonce16 {
    (
        $wrapping_key: expr,
        $key_to_unwrap: expr,
        $tag: expr,
        $nonce: expr
    ) => {{
        let cipher = Aes256GcmN16::new($wrapping_key);

        let mut key = $key_to_unwrap.clone();

        let iv = Aes256GcmNonce16::from_slice($nonce);
        let tag = Aes256GcmTag::from_slice($tag);

        let associated_data = b"";

        cipher
            .decrypt_in_place_detached(iv, associated_data, key.as_mut_slice(), tag)
            .map_err(|_| TpmError::Aes256GcmDecrypt)?;

        if key.as_slice() == $key_to_unwrap.as_slice() {
            // Encryption didn't replace the buffer in place, fail.
            return Err(TpmError::Aes256GcmDecrypt);
        }

        Ok(key)
    }};
}

pub(crate) use unwrap_aes256gcm_nonce16;
