use crate::{
    gateway,
    poc::store::PoCStore,
    service::gateway::{Challenge, ChallengeCheck, GatewayService},
    traits::Base64,
    CacheSettings, Keypair, Result,
};
use futures::TryFutureExt;
use helium_proto::BlockchainRegionParamsV1;
use slog::{info, o, warn, Logger};
use std::sync::Arc;
use tokio::{
    sync::mpsc,
    time::{self, Duration, MissedTickBehavior},
};

pub const CHECK_WAITING_CHALLENGE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug)]
pub enum Message {
    Challenge(Challenge),
}

#[derive(Clone, Debug)]
pub struct MessageSender(pub(crate) mpsc::Sender<Message>);
pub type MessageReceiver = mpsc::Receiver<Message>;

pub fn message_channel(size: usize) -> (MessageSender, MessageReceiver) {
    let (tx, rx) = mpsc::channel(size);
    (MessageSender(tx), rx)
}

impl MessageSender {
    pub async fn challenge(&self, challenge: Challenge) {
        let _ = self.0.send(Message::Challenge(challenge)).await;
    }
}

pub struct PoCClient {
    keypair: Arc<Keypair>,
    downlinks: gateway::MessageSender,
    region_params: Option<BlockchainRegionParamsV1>,
    store: PoCStore,
}

impl PoCClient {
    pub async fn new(
        keypair: Arc<Keypair>,
        downlinks: gateway::MessageSender,
        settings: &CacheSettings,
    ) -> Result<Self> {
        let store = PoCStore::new(settings);
        Ok(Self {
            keypair,
            downlinks,
            store,
            region_params: None,
        })
    }

    pub async fn run(
        &mut self,
        mut messages: MessageReceiver,
        shutdown: triggered::Listener,
        logger: &Logger,
    ) -> Result {
        let logger = logger.new(o!(
            "module" => "poc",
        ));
        info!(logger, "starting");

        let mut waiting_timer = time::interval(CHECK_WAITING_CHALLENGE_INTERVAL);
        waiting_timer.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = shutdown.clone() => {
                    info!(logger, "shutting down");
                    return Ok(())
                },
                message = messages.recv() => match message {
                    Some(Message::Challenge(challenge)) => {
                        let _ = self.handle_challenge(&logger, challenge)
                            .inspect_err(|err| warn!(logger, "ignoring failed challenge {:?}", err))
                            .await;
                    },
                    None => warn!(logger, "ignoring closed message channel"),
                }
            }
        }
    }

    async fn handle_challenge(&mut self, logger: &Logger, challenge: Challenge) -> Result {
        let mut challenger = GatewayService::new(&challenge.challenger)?;
        match challenger
            .poc_check_challenge_target(self.keypair.clone(), &challenge)
            .await
        {
            // Not the target of this challenge
            Ok(ChallengeCheck::NotTarget) => {
                info!(logger, "ignoring challenge, not target";
                    "challenge" => challenge.onion_key_hash.to_b64url());
                Ok(())
            }
            Ok(ChallengeCheck::Target(onion)) => {
                self.store
                    .remove_waiting_challenge(&challenge.onion_key_hash);
                self.handle_onion(logger, &onion).await
            }
            // The POC key exists but the POC itself may not yet be initialised
            // this can happen if the challenging validator is behind our
            // notifying validator if the challenger is behind the notifier or
            // hasn't started processing the challenge block yet, then cache
            // the check target req it will then be retried periodically
            Ok(ChallengeCheck::Queued(challenger_height))
                if challenge.height >= challenger_height =>
            {
                let onion_key_hash = challenge.onion_key_hash.clone();
                if self
                    .store
                    .store_waiting_challenge(&onion_key_hash, challenge)
                {
                    info!(logger, "queued challenge";
                        "challenge" => onion_key_hash.to_b64url());
                } else {
                    warn!(logger, "dropped challenge, cache size reached";
                        "challenge" => onion_key_hash.to_b64url());
                }
                Ok(())
            }
            // Ignore challenger height beyond the challenge height. This should
            // not happen
            Ok(ChallengeCheck::Queued(_)) => Ok(()),
            // An error occured talking to the challenger, remove waiting challenge
            Err(err) => {
                self.store
                    .remove_waiting_challenge(&challenge.onion_key_hash);
                Err(err)
            }
        }
    }

    async fn handle_onion(&mut self, logger: &Logger, onion: &[u8]) -> Result {
        if self.region_params.is_none() {
            warn!(logger, "dropping challenge, no region params";
                "challenge" => onion.to_b64url()
            );
            return Ok(());
        }
        Ok(())
    }
}
