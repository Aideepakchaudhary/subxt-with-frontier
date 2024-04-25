// Copyright 2019-2023 Parity Technologies (UK) Ltd.
// This file is dual-licensed as Apache-2.0 or GPL-3.0.
// see LICENSE for license details.

//! An ecdsa keypair implementation.
use hex::FromHex;
use secp256k1::{ecdsa, Message, Keypair, SecretKey, SECP256K1};
use keccak_hash::keccak;

#[derive(Debug)]
pub struct EthereumSigner(Keypair);

impl EthereumSigner {
    pub fn from_private_key_hex(hex: &str) -> Result<EthereumSigner, anyhow::Error> {
        let seed = <[u8; 32]>::from_hex(hex)?;
        let secret = SecretKey::from_slice(&seed)?;
        Ok(EthereumSigner(secp256k1::Keypair::from_secret_key(
            SECP256K1, &secret,
        )))
    }

    pub fn public_key(&self) -> secp256k1::PublicKey {
        self.0.public_key()
    }

    pub fn account_id(&self) -> AccountId20 {
        let uncompressed = self.0.public_key().serialize_uncompressed();
        let hash = keccak(&uncompressed[1..]).0;
        let hash20 = hash[12..].try_into().expect("should be 20 bytes");
        AccountId20(hash20)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, codec::Encode)]
pub struct EthereumSignature(pub [u8; 65]);

#[derive(Debug, Copy, Clone, codec::Encode)]
pub struct AccountId20(pub [u8; 20]);

impl AsRef<[u8]> for AccountId20 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl <T: subxt::Config> subxt::tx::Signer<T> for EthereumSigner
    where
        T::AccountId: From<AccountId20>,
        T::Address: From<AccountId20>,
        T::Signature: From<EthereumSignature>
{
    fn account_id(&self) -> T::AccountId {
        self.account_id().into()
    }

    fn address(&self) -> T::Address {
        self.account_id().into()
    }

    fn sign(&self, signer_payload: &[u8]) -> T::Signature {
        // The below is copied from subxt_signer's ecdsa signing; the only change
        // is that we hash the message with keccak and not blake2_256, above, to
        // match what the runtime verification does

        let message_hash = keccak(signer_payload);
        let wrapped = Message::from_digest_slice(message_hash.as_bytes()).expect("Message is 32 bytes; qed");
        let recsig: ecdsa::RecoverableSignature =
            SECP256K1.sign_ecdsa_recoverable(&wrapped, &self.0.secret_key());
        let (recid, sig) = recsig.serialize_compact();
        let mut signature_bytes: [u8; 65] = [0; 65];
        signature_bytes[..64].copy_from_slice(&sig);
        signature_bytes[64] = (recid.to_i32() & 0xFF) as u8;
        EthereumSignature(signature_bytes).into()
    }
}
