use crate::{Error, Keypair, PublicKey, Result};
use aes_gcm::{
    aead::{Aead, NewAead, Payload},
    Aes256Gcm, Nonce,
};
use bytes::{Buf, BufMut};
use std::sync::Arc;

#[derive(Debug)]
pub struct Onion {
    pub iv: u16,
    pub public_key: PublicKey,
    pub tag: [u8; 4],
    pub cipher_text: Vec<u8>,
}

impl Onion {
    pub fn from(mut data: &[u8]) -> Result<Self> {
        if data.len() < 39 {
            return Err(Error::custom("invalid onion size"));
        }
        let iv = data.get_u16_le();
        let public_key = PublicKey::from_bytes(&data.copy_to_bytes(33))?;
        let mut tag = [0u8; 4];
        data.copy_to_slice(&mut tag);
        let cipher_text = data.to_vec();
        Ok(Self {
            iv,
            public_key,
            tag,
            cipher_text,
        })
    }

    pub fn decrypt(&self, keypair: Arc<Keypair>, msg: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let shared_secret = keypair.ecdh(&keypair.public_key())?;

        let onion_keybin = self.public_key.to_vec();

        const IV_LENGTH: usize = 12;
        let aad = [0u8; IV_LENGTH + helium_crypto::ecc_compact::PUBLIC_KEY_LENGTH];

        {
            let mut aad = &mut aad[..];
            aad.put_bytes(0, 10);
            aad.put_u16_le(self.iv);
            aad.put_slice(&onion_keybin);
        }

        let cipher = Aes256Gcm::new(shared_secret.as_bytes());
        let nonce = Nonce::from_slice(&aad[..IV_LENGTH]);
        let payload = Payload { msg, aad: &aad };
        let result = cipher.decrypt(nonce, payload)?;
        Ok(result)
    }
}
