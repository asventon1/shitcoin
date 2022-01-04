use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey, PaddingScheme, Hash};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

pub fn generate_key_pair() -> (RsaPrivateKey, RsaPublicKey) {
  let mut rng = OsRng;
  let bits = 2048;
  let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
  let public_key = RsaPublicKey::from(&private_key);
  (private_key, public_key)
}

pub fn sign_message(message: String, private_key: &RsaPrivateKey) -> Vec<u8>{
  let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
  let mut hasher = Sha256::new();
  hasher.update(message);
  let hash = hasher.finalize();
  let signature = private_key.sign(padding, &hash).expect("failed to sign message");
  signature
}

pub fn verify_message(message: String, signature: &Vec<u8>, public_key: &RsaPublicKey) -> bool {
  let padding = PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256));
  let mut hasher = Sha256::new();
  hasher.update(message);
  let hash = hasher.finalize();
  match public_key.verify(padding, &hash, &signature[..]) {
    Ok(_) => true,
    Err(_) => false,
  }
}

pub type SHA256Hash = [u8; 32];

#[derive(Debug)]
pub struct Transaction {
  sender: RsaPublicKey,
  reciver: RsaPublicKey,
  amount: f64,
  uid: u64,
  signature: Vec<u8>,
}

impl Transaction {
  pub fn new(sender: RsaPublicKey, sender_private_key: RsaPrivateKey, reciver: RsaPublicKey, amount: f64, uid: u64) -> Self {
    let transaction_string = format!("{:?} {:?} {:?} {:?}", sender, reciver, amount, uid);
    //println!("{}", transaction_string);
    let signature = sign_message(transaction_string, &sender_private_key);
    //println!("{:?}", signature);
    Transaction { sender, reciver, amount, uid, signature }
  }

  pub fn verify(&self) -> bool {
    let transaction_string = format!("{:?} {:?} {:?} {:?}", self.sender, self.reciver, self.amount, self.uid);
    verify_message(transaction_string, &self.signature, &self.sender)
  }
}

struct Block {
  transactions: Vec<Transaction>,
  nonce: u64,
  miner: RsaPublicKey,
  hash: SHA256Hash,
}

impl Block {

  #[inline(always)]
  fn check_block(transactions: &Vec<Transaction>, miner: &RsaPublicKey, nonce: u64) -> (bool, SHA256Hash) {
    let mut hasher = Sha256::new();
    let block_string = format!("{:?} {:?} {:?}", transactions, miner, nonce);
    hasher.update(block_string.as_bytes());
    let hash = hasher.finalize();
    let mut is_zeros = true;
    for i in 0..4 {
      if hash[i] != 0 {
        is_zeros = false;
        break;
      }
    }
    (is_zeros, SHA256Hash::from(hash))
  }

  fn mine_block(transactions: Vec<Transaction>, miner: RsaPublicKey) -> SHA256Hash {
    for i in 0 as u64.. {
      let (is_correct, hash) = Self::check_block(&transactions, &miner, i);
      if is_correct {
        return hash;
      }
    }
    panic!("Couldn't find a nonce to mine block");
  }
}

#[cfg(test)]
mod tests {
  use super::*; 

  #[test]
  fn test_transaction_correct() {
    let (private_key, public_key) = generate_key_pair();
    let (_private_key2, public_key2) = generate_key_pair();
    let transaction = Transaction::new(public_key, private_key, public_key2, 10.0, 1);
    let is_good = transaction.verify();
    assert_eq!(is_good, true);
  }

  #[test]
  fn test_transaction_change_amount() {
    let (private_key, public_key) = generate_key_pair();
    let (_private_key2, public_key2) = generate_key_pair();
    let mut transaction = Transaction::new(public_key, private_key, public_key2, 10.0, 1);
    transaction.amount = 100.0;
    let is_good = transaction.verify();
    assert_eq!(is_good, false);
  }

  #[test]
  fn test_transaction_change_reciver() {
    let (private_key, public_key) = generate_key_pair();
    let (_private_key2, public_key2) = generate_key_pair();
    let (_private_key2, public_key3) = generate_key_pair();
    let mut transaction = Transaction::new(public_key, private_key, public_key2, 10.0, 1);
    transaction.reciver = public_key3;
    let is_good = transaction.verify();
    assert_eq!(is_good, false);
  }

  #[test]
  fn test_transaction_change_uid() {
    let (private_key, public_key) = generate_key_pair();
    let (_private_key2, public_key2) = generate_key_pair();
    let (_private_key2, public_key3) = generate_key_pair();
    let mut transaction = Transaction::new(public_key, private_key, public_key2, 10.0, 1);
    transaction.uid = 2;
    let is_good = transaction.verify();
    assert_eq!(is_good, false);
  }

  #[test]
  fn test_signing_correct() {
    let (private_key, public_key) = generate_key_pair();
    let signature = sign_message("hello".to_string(), &private_key);
    let is_good = verify_message("hello".to_string(), &signature, &public_key);
    assert_eq!(is_good, true);
  }

  #[test]
  fn test_signing_message_change() {
    let (private_key, public_key) = generate_key_pair();
    let signature = sign_message("hello".to_string(), &private_key);
    let is_good = verify_message("goodbye".to_string(), &signature, &public_key);
    assert_eq!(is_good, false);
  }

  #[test]
  fn test_signing_bad_signature() {
    let (private_key, public_key) = generate_key_pair();
    let mut signature = sign_message("hello".to_string(), &private_key);
    signature[0] = if signature[0] == 15 { 16 } else { 15 };
    let is_good = verify_message("hello".to_string(), &signature, &public_key);
    assert_eq!(is_good, false);
  }
}