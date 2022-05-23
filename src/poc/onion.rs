use crate::{error::OnionError, Error, Keypair, PublicKey, Result};
use aes_gcm::{
    aes::{
        cipher::{FromBlockCipher, StreamCipher},
        Aes256, BlockEncrypt, NewBlockCipher,
    },
    Tag, C_MAX,
};
use bytes::{Buf, BufMut};
use ctr::Ctr32BE;
use ghash::{
    universal_hash::{NewUniversalHash, UniversalHash},
    GHash,
};
use std::sync::Arc;
pub const TAG_LENGTH: usize = 4;
pub const NONCE_LENGTH: usize = 12;

#[derive(Debug)]
pub struct Onion {
    pub iv: u16,
    pub public_key: PublicKey,
    pub tag: [u8; TAG_LENGTH],
    pub cipher_text: Vec<u8>,
}

impl Onion {
    pub fn from(mut data: &[u8]) -> Result<Self> {
        if data.len() < 39 {
            return Err(Error::custom("invalid onion size"));
        }
        let iv = data.get_u16_le();
        let public_key = PublicKey::from_bytes(&data.copy_to_bytes(33))
            .map_err(|_| OnionError::invalid_key())?;
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

    pub fn decrypt_in_place(&self, keypair: Arc<Keypair>, buffer: &mut [u8]) -> Result {
        if buffer.len() as u64 > C_MAX {
            return Err(OnionError::invalid_size(buffer.len()));
        }

        let onion_keybin = self.public_key.to_vec();

        let mut aad = [0u8; NONCE_LENGTH + helium_crypto::ecc_compact::PUBLIC_KEY_LENGTH];

        {
            let mut aad = &mut aad[10..];
            aad.put_u16_le(self.iv);
            aad.put_slice(&onion_keybin);
        }

        let shared_secret = keypair.ecdh(&self.public_key)?;
        let cipher = Aes256::new(shared_secret.as_bytes());
        let nonce = &aad[..NONCE_LENGTH];

        let mut expected_tag = self.compute_tag(&cipher, &aad, &buffer);
        let mut ctr = self.init_ctr(&cipher, nonce);
        ctr.apply_keystream(expected_tag.as_mut_slice());

        if !expected_tag.starts_with(&self.tag) {
            return Err(OnionError::crypto_error());
        }

        ctr.apply_keystream(buffer);
        Ok(())
    }

    /// Initialize counter mode.
    ///
    /// TODO: Reference aes_gcm block
    fn init_ctr<'a>(&self, cipher: &'a Aes256, nonce: &[u8]) -> Ctr32BE<&'a Aes256> {
        let j0 = {
            let mut block = ghash::Block::default();
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            block
        };
        Ctr32BE::from_block_cipher(&cipher, &j0)
    }

    fn compute_tag(&self, cipher: &Aes256, aad: &[u8], buffer: &[u8]) -> Tag {
        let mut ghash_key = ghash::Key::default();
        cipher.encrypt_block(&mut ghash_key);

        let ghash = GHash::new(&ghash_key);

        let mut ghash = ghash.clone();
        ghash.update_padded(aad);
        ghash.update_padded(buffer);

        let associated_data_bits = (aad.len() as u64) * 8;
        let buffer_bits = (buffer.len() as u64) * 8;

        let mut block = ghash::Block::default();
        block[..8].copy_from_slice(&associated_data_bits.to_be_bytes());
        block[8..].copy_from_slice(&buffer_bits.to_be_bytes());
        ghash.update(&block);
        ghash.finalize().into_bytes()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn decrypt() {
        // Consructed using libp2p_crypto as the gateway keypaor
        const GW_KEYPAIR: &[u8] = &hex!("004956DB80645842ED4C938BD625DF3D99674729C6D9021025C8390C5ACFB93A4404911E9B3E4199F61BF47736D01100D5DF0FF57BCCBF61BDA4DF6CCA51B62040F409D50F6890CB91B513CAE429054C5E068DF44DC80DCE43EF361DD2E6530BBA81");
        // Constructed by creating an onion keypair in libp2p_crypto and copying
        // the pubkey_to_bin
        const ONION_PUBKEY: &[u8] =
            &hex!("00A8731EAD55027001185D153258530E682EA66374357C28D181E542AA497E4415");
        // Constructed by doing an ECDH with the onion private key and the
        // public gw key from the keypair to get the shared secret.
        // Then using the shared secret to call
        //
        // Plaintext = "hello world".
        // IV0 = 42.
        // IV = <<0:80/integer, IV0:16/integer-unsigned-little>>.
        // OnionPubKeyBin = libp2p_crypto:pubkey_to_bin(OnionPubKey).
        // AAD = <<IV/binary, OnionPubKeyBin/binary>>.
        // {CipherText, Tag} = crypto:crypto_one_time_aead(aes_256_gcm, SharedSecret, IV, PlainText, AAD, 4, true).
        //
        // To encrypt the content to thsi cipher text and tag
        const CIPHER_TEXT: &[u8] = &hex!("F3E49EB69F2783A1A087C9");
        const TAG: [u8; 4] = hex!("3E031987");

        let gw_keypair = helium_crypto::Keypair::try_from(GW_KEYPAIR).expect("gw keypair");
        let onion_pubkey = helium_crypto::PublicKey::try_from(ONION_PUBKEY).expect("onion pubkey");

        let onion = Onion {
            iv: 42,
            public_key: onion_pubkey,
            tag: TAG,
            cipher_text: CIPHER_TEXT.to_vec(),
        };
        let mut plain_text = onion.cipher_text.clone();
        onion
            .decrypt_in_place(Arc::new(gw_keypair.into()), &mut plain_text)
            .expect("decrypt");

        assert_eq!(
            "hello world".to_string(),
            String::from_utf8(plain_text).expect("plain text")
        );
    }
}
