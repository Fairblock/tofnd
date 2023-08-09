// error handling
use crate::TofndResult;
use anyhow::anyhow;

use tofn::{collections::TypedUsize, gg20::keygen::malicious::Behaviour as KeygenBehaviour};

use clap::App;

pub(super) type Behaviours = crate::gg20::service::malicious::Behaviours;

pub(super) const AVAILABLE_BEHAVIOURS: [&str; 4] = [
    "Honest",
    "R2BadShare",
    "R2BadEncryption",
    "R3FalseAccusation",
];

pub fn get_behaviour_matches(app: App) -> TofndResult<Behaviours> {
    // TODO: if we want to read all available behaviours from tofn automatically,
    // we should add strum (https://docs.rs/strum) to iterate over enums and
    // print their names, but it has to be imported in tofn.

    let matches = app.get_matches();

    // Set a default behaviour
    let mut behaviour = "Honest";
    let mut victim = vec![0];
    let mut faulty = vec![1];
    if let Some(matches) = matches.subcommand_matches("malicious") {
        behaviour = matches
            .value_of("behaviour")
            .ok_or_else(|| anyhow!("behaviour value"))?;
        let victim_str = matches
        .value_of("victim")
        .ok_or_else(|| anyhow!("victim value"))?;
    
    let victim: Result<Vec<usize>, _> = victim_str
        .split(',')
        .map(|s| s.parse::<usize>())
        .collect();
    
    let victim: Vec<usize> = victim.unwrap();
    let faulty_str = matches
    .value_of("faulty")
    .ok_or_else(|| anyhow!("faulty value"))?;

let faulty: Result<Vec<usize>, _> = faulty_str
    .split(',')
    .map(|s| s.parse::<usize>())
    .collect();

let faulty: Vec<usize> = faulty.unwrap();

    }

    // TODO: parse keygen malicious types as well
    //  let keygen = KeygenBehaviour::R1BadCommit;
    let keygen = match_string_to_behaviour(behaviour, victim, faulty);
    Ok(Behaviours { keygen })
}

fn match_string_to_behaviour(
    behaviour: &str,
    _victim: Vec<usize>,
    _faulty: Vec<usize>,
) -> KeygenBehaviour {
    use KeygenBehaviour::*;
    // let victim = TypedUsize::from_usize(victim);
    let victim= _victim.iter().map(|&x| TypedUsize::from_usize(x)).collect();
    let faulty= _faulty.iter().map(|&x| TypedUsize::from_usize(x)).collect();
    // let faulty = TypedUsize::from_usize(faulty);
    // TODO: some of the behaviours do not demand a victim. In the future, more
    // will be added that potentially need different set of arguments.
    // Adjust this as needed to support that.
    match behaviour {
        "Honest" => Honest,
        "R2BadShare" => R2BadShare { victim, faulty },
        "R2BadEncryption" => R2BadEncryption { victim },
        "R3FalseAccusation" => R3FalseAccusation { victim, faulty },
        _ => Honest,
    }
}
