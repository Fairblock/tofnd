//! Abstract functionality used by keygen, sign, etc.

use std::{convert::TryInto, time::Duration};
use group::GroupEncoding;
use bls12_381::G1Affine;
use tofn::{
    collections::TypedUsize,
    sdk::api::{Protocol, ProtocolOutput, Round},
};
use serde_json;
// tonic cruft
use super::{proto, ProtocolCommunication};
use tokio::{sync::mpsc::{UnboundedReceiver, UnboundedSender}, time::timeout};
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct, Deserializer};
// logging
use tracing::{debug, error, span, warn, Level, Span};

// error handling
use crate::TofndResult;
use anyhow::anyhow;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pSad {
    pub(super) vss_complaint: Vec<ShareInfoDispute>,
}
#[derive(Debug, Clone)]
pub(super) struct ShareInfoDispute {
    pub(super) share: Share,
    pub(super) kij: bls12_381::G1Projective,
    pub(super) proof: ([u8; 32], [u8;32])
}
#[derive(Clone, Debug, PartialEq)]

pub struct Share {
    scalar: bls12_381::Scalar,
    index: usize,
}
impl<'de> Deserialize<'de> for ShareInfoDispute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        
        let (share, mut r, p) = <(Share, [u8;32], ([u8; 32], [u8;32]))>::deserialize(deserializer)?;
      let r_vec: & [u8] = r.as_mut();
        let kij = G1Affine::from_compressed(r_vec.try_into().unwrap()).unwrap().into();
        Ok(ShareInfoDispute { share: share, kij: kij, proof: p } )
    }
}
impl Serialize for ShareInfoDispute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut shareDispute = serializer.serialize_struct("ShareInfoDispute",3).unwrap();
        shareDispute.serialize_field("share", &self.share)?;
        shareDispute.serialize_field("kij", &self.kij.to_bytes().as_ref())?;
        shareDispute.serialize_field("proof", &self.proof)?;
        shareDispute.end()
        
    }
}
impl<'de> Deserialize<'de> for Share {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        
        let (c, r) = <([u8;32], usize)>::deserialize(deserializer)?;
        let shareScalar = bls12_381::Scalar::from_bytes(&c).unwrap();
    
        Ok(Share { scalar:shareScalar, index: r })
    }
}
impl From<Share> for (bls12_381::Scalar, usize) {
    fn from(share: Share) -> (bls12_381::Scalar, usize) {
        let scalar = share.scalar;
        (scalar, share.index)
    }
}
impl Serialize for Share {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (scalar, index) = self.clone().into();
        let mut state = serializer.serialize_struct("Share", 2)?;
        state.serialize_field("scalar", &scalar.to_bytes())?;
        state.serialize_field("index", &index)?;
        state.end()
    }
}
/// execute gg20 protocol
pub(super) async fn execute_protocol<F, K, P, const MAX_MSG_IN_LEN: usize>(
    mut party: Protocol<F, K, P, MAX_MSG_IN_LEN>,
    mut chans: ProtocolCommunication<
        Option<proto::TrafficIn>,
        Result<proto::MessageOut, tonic::Status>,
    >,
    party_uids: &[String],
    party_share_counts: &[usize],
    span: Span,
) -> TofndResult<ProtocolOutput<F, P>>
where
    K: Clone,
{
    // set up counters for logging
    let total_num_of_shares = party_share_counts.iter().fold(0, |acc, s| acc + *s);
    let mut total_round_p2p_msgs = total_num_of_shares * (total_num_of_shares - 1); // total number of messages is n(n-1)

    let mut round_count = 0;
    while let Protocol::NotDone(mut round) = party {
        round_count += 1;
        debug!("here: {}", round_count);
        // handle outgoing traffic
        handle_outgoing(&chans.sender, &round, party_uids, round_count, span.clone())?;
//debug!("round {} : p2ps = {} bcasts = {}", round_count, total_round_p2p_msgs,total_num_of_shares);
        // collect incoming traffic
       // debug!("outgoing sent: {}", round_count);
        handle_incoming(
            &mut chans.receiver,
            &mut round,
            party_uids,
            total_round_p2p_msgs,
            total_num_of_shares,
            round_count,
            span.clone(),
        )
        .await?;
//debug!("here: {}", round_count);
        // check if everything was ok this round
        party = round
            .execute_next_round()
            .map_err(|_| anyhow!("Error in tofn::execute_next_round"))?;
    }

    match party {
        Protocol::NotDone(_) => Err(anyhow!("Protocol failed to complete")),
        Protocol::Done(result) => Ok(result),
    }
}

fn handle_outgoing<F, K, P, const MAX_MSG_IN_LEN: usize>(
    sender: &UnboundedSender<Result<proto::MessageOut, tonic::Status>>,
    round: &Round<F, K, P, MAX_MSG_IN_LEN>,
    party_uids: &[String],
    round_count: usize,
    span: Span,
) -> TofndResult<()> {
    let send_span = span!(parent: &span, Level::DEBUG, "outgoing", round = round_count);
    let _start = send_span.enter();
   
    // send outgoing bcasts
    if let Some(bcast) = round.bcast_out() {
       // debug!("generating out bcast");
        // send message to gRPC client
     //   let string = String::from_utf8(*bcast).unwrap();
     if round.info().round() == 2{
        sender.send(Ok(proto::MessageOut::new_bcast_r3(bcast)))?
     }else{
        sender.send(Ok(proto::MessageOut::new_bcast(bcast)))?
     }
        
    }
    
    // send outgoing p2ps
    if let Some(p2ps_out) = round.p2ps_out() {

        let mut p2p_msg_count = 1;
        for (i, p2p) in p2ps_out.iter() {
            // get tofnd index from tofn
            let tofnd_idx = round
                .info()
                .party_share_counts()
                .share_to_party_id(i)
                .map_err(|_| anyhow!("Unable to get tofnd index for party {}", i))?;

            debug!(
                "out p2p to [{}] ({}/{})",
                party_uids[tofnd_idx.as_usize()],
                p2p_msg_count,
                p2ps_out.len() - 1
            );
            p2p_msg_count += 1;
//debug!("round number is {}",round.info().round());
//    if round.info().round() == 2{
//         let result: Result<P2pSad, serde_json::Error> =
//         serde_json::from_slice(&p2p);
// debug!("round 3");
//     match result {
//         Ok(deserialized) => {
//             debug!("deserialized: {:?}", deserialized);
//         }
//         Err(err) => {
//             debug!("Deserialization error: {}", err);
//         }
//     }}
            // send message to gRPC client
            sender.send(Ok(proto::MessageOut::new_p2p(
                &party_uids[tofnd_idx.as_usize()],
                p2p,
            )))?
        }
    }
    
    Ok(())
}

async fn handle_incoming<F, K, P, const MAX_MSG_IN_LEN: usize>(
    receiver: &mut UnboundedReceiver<Option<proto::TrafficIn>>,
    round: &mut Round<F, K, P, MAX_MSG_IN_LEN>,
    party_uids: &[String],
    total_round_p2p_msgs: usize,
    total_num_of_shares: usize,
    round_count: usize,
    span: Span,
) -> TofndResult<()> {
    let mut p2p_msg_count = 0;
    let mut bcast_msg_count = 0;
    
    let mut i = 0;
    let mut continue_loop = round.expecting_more_msgs_this_round(); 
    // loop until no more messages are needed for this round
    while continue_loop {
        
        i = i+ 1;
        // get internal message from broadcaster
        // let timeout_duration = Duration::from_secs(15); // Timeout duration of 2 minutes

        // let traffic = timeout(timeout_duration, receiver.recv()).await.map_err(|_| {
        //     format!(
        //         "{}: stream closed by client or timed out before protocol has completed",
        //         round_count
        //     )
        // });
        let traffic = receiver.recv().await.ok_or(format!(
            "{}: stream closed by client before protocol has completed",
            round_count
        ));
      
       // debug!("now {}",i);
        // unpeel TrafficIn
        let traffic = match traffic.clone() {
            Ok(traffic_opt) => match traffic_opt {
                Some(traffic) => traffic,
                None => {
                    // if data is missing, ignore the message,
                    warn!("ignore incoming msg: missing `data` field");
                    continue;
                }
            },
            Err(_) => {
                // if channel is closed, stop
                error!("internal channel closed prematurely");
                break;
            }
        };
        if traffic.clone().payload == "timeout".as_bytes().to_vec(){
            continue_loop = false;
            break;
        }
       // debug!("then {}",i);
        // We have to spawn a new span it in each loop because `async` calls don't work well with tracing
        // See details on how we need to make spans curve around `.await`s here:
        // https://docs.rs/tracing/0.1.25/tracing/span/index.html#entering-a-span
        let recv_span = span!(parent: &span, Level::DEBUG, "incoming", round = round_count);
        let _start = recv_span.enter();

        // log incoming message
        if traffic.clone().is_broadcast {
            bcast_msg_count += 1;
            debug!(
                "{} got incoming bcast message {}/{}",round.info().party_id().to_string(),
                bcast_msg_count, total_num_of_shares
            );
        } else {
            p2p_msg_count += 1;
            debug!(
                "{} got incoming p2p message {}/{}",round.info().party_id().to_string(),
                p2p_msg_count, total_round_p2p_msgs
            );
        }
   
      //  debug!("traffic: {:?}", traffic.clone());
        // get sender's party index 
        let from = party_uids
            .iter()
            .position(|uid| uid == &traffic.clone().from_party_uid)
            .ok_or_else(|| anyhow!("from uid does not exist in party uids"))?;

        // try to set a message
        if round_count == 3{
            if round
            .msg_inr4(TypedUsize::from_usize(from), &traffic.clone().payload)
            .is_err()
        {
            return Err(anyhow!("error calling tofn::msg_in with [from: {}]", from));
        };
        }
        if round_count != 3{
        if round
            .msg_in(TypedUsize::from_usize(from), &traffic.payload)
            .is_err()
        {
            return Err(anyhow!("error calling tofn::msg_in with [from: {}]", from));
        };}
        continue_loop = round.expecting_more_msgs_this_round(); 
        
    

    }

    Ok(())
}
