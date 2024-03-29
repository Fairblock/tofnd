//! Wrappers for sending and receiving [proto] messages

use tofn::{collections::FillVecMap, gg20::keygen::KeygenPartyId, sdk::api::Fault};

use crate::proto;
type KeygenFaults = FillVecMap<KeygenPartyId, Fault>;
type KeygenResultData = Result<proto::KeygenOutput, KeygenFaults>;
use proto::message_out::criminal_list::criminal::CrimeType as ProtoCrimeType;
use proto::message_out::criminal_list::Criminal as ProtoCriminal;
use proto::message_out::keygen_result::KeygenResultData::Criminals as ProtoKeygenCriminals;
use proto::message_out::keygen_result::KeygenResultData::Data as ProtoKeygenData;
use proto::message_out::CriminalList as ProtoCriminalList;

// convenience constructors
impl proto::MessageOut {
    pub(super) fn new_bcast(bcast: &[u8], round_num: &str) -> Self {
        Self::new_traffic("", bcast, true, round_num)
    }
    pub(super) fn new_bcast_r3(bcast: &[u8], round_num: &str) -> Self {
        Self::new_traffic("r3", bcast, true, round_num)
    }
    pub(super) fn new_p2p(receiver_id: &str, p2p: &[u8], round_num: &str) -> Self {
        Self::new_traffic(receiver_id, p2p, false, round_num)
    }
    pub(super) fn new_traffic(
        receiver_id: &str,
        msg: &[u8],
        is_broadcast: bool,
        round_num: &str,
    ) -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::Traffic(proto::TrafficOut {
                to_party_uid: receiver_id.to_string(),
                payload: msg.to_vec(),
                is_broadcast,
                round_num: round_num.to_string(),
            })),
        }
    }
    pub(super) fn need_recover() -> Self {
        proto::MessageOut {
            data: Some(proto::message_out::Data::NeedRecover(true)),
        }
    }

    pub(super) fn new_keygen_result(participant_uids: &[String], result: KeygenResultData) -> Self {
        let result = match result {
            Ok(keygen_output) => ProtoKeygenData(keygen_output),
            Err(faults) => ProtoKeygenCriminals(ProtoCriminalList::from_tofn_faults(
                faults,
                participant_uids,
            )),
        };
        proto::MessageOut {
            data: Some(proto::message_out::Data::KeygenResult(
                proto::message_out::KeygenResult {
                    keygen_result_data: Some(result),
                },
            )),
        }
    }
}

fn fault_to_crime(f: &Fault) -> ProtoCrimeType {
    match f {
        Fault::MissingMessage | Fault::CorruptedMessage => ProtoCrimeType::NonMalicious,
        Fault::ProtocolFault => ProtoCrimeType::Malicious,
    }
}

impl ProtoCriminalList {
    fn from_tofn_faults<P>(faults: FillVecMap<P, Fault>, uids: &[String]) -> Self {
        let criminals = faults
            .into_iter_some()
            .map(|(i, fault)| ProtoCriminal {
                party_uid: uids[i.as_usize()].clone(),
                crime_type: fault_to_crime(&fault) as i32, // why `as i32`? https://github.com/danburkert/prost#enumerations
            })
            .collect();
        Self { criminals }
    }
}
