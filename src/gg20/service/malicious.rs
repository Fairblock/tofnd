use tofn::gg20::{
    keygen::malicious::Behaviour as KeygenBehaviour
};

/// Behaviours are pub because config mod needs access
#[derive(Clone, Debug)]
pub struct Behaviours {
    pub keygen: KeygenBehaviour,
 
}
