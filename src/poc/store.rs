use crate::{service::gateway::Challenge, CacheSettings, Result};
use std::{
    collections::HashMap,
    ops::Deref,
    time::{Duration, Instant},
};

pub struct PoCStore {
    waiting_challenges: HashMap<Vec<u8>, QueueChallenge>,
    max_challenges: u16,
}
#[derive(Debug)]
pub struct QueueChallenge {
    challenge: Challenge,
    received: Instant,
}

impl PartialEq for QueueChallenge {
    fn eq(&self, other: &Self) -> bool {
        self.challenge.onion_key_hash == other.onion_key_hash
    }
}

impl Eq for QueueChallenge {}

impl Deref for QueueChallenge {
    type Target = Challenge;

    fn deref(&self) -> &Self::Target {
        &self.challenge
    }
}

impl From<Challenge> for QueueChallenge {
    fn from(challenge: Challenge) -> Self {
        let received = Instant::now();
        Self {
            received,
            challenge,
        }
    }
}

impl PoCStore {
    pub fn new(settings: &CacheSettings) -> Self {
        let max_challenges = settings.max_challenges;
        let waiting_challenges = HashMap::new();
        Self {
            waiting_challenges,
            max_challenges,
        }
    }

    pub fn store_waiting_challenge(&mut self, onion_key_hash: &[u8], challenge: Challenge) -> bool {
        if self.has_waiting_challenge(onion_key_hash) {
            return true;
        }
        if self.waiting_challenges.len() > self.max_challenges as usize {
            return false;
        }
        self.waiting_challenges
            .insert(onion_key_hash.to_vec(), QueueChallenge::from(challenge));
        true
    }

    pub fn waiting_challenges_len(&self) -> usize {
        self.waiting_challenges.len()
    }

    pub fn remove_waiting_challenge(&mut self, onion_key_hash: &[u8]) -> Option<QueueChallenge> {
        self.waiting_challenges.remove(&onion_key_hash.to_vec())
    }

    pub fn has_waiting_challenge(&self, onion_key_hash: &[u8]) -> bool {
        self.waiting_challenges.contains_key(onion_key_hash)
    }
}
