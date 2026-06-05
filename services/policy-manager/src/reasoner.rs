use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
};

use clingo::{control, ClingoError, FactBase, Part, Symbol};

use crate::entities::{Issuer, MetaPolicy, Policy, PolicyId, DEFAULT_ISSUER};
use crate::policy_manager as pb;

const SYMBOL_SRC: &str = "src";
const SYMBOL_DST: &str = "dst";
const SYMBOL_PATH: &str = "path";
const SYMBOL_IN_PATH: &str = "in_path";
const SYMBOL_CHOSEN_PATH: &str = "chosen_path";
const SYMBOL_HAS_METADATA: &str = "has_metadata";
const SYMBOL_ISSUED: &str = "issued";
const SYMBOL_POWER: &str = "power";
const SYMBOL_CONFLICTING: &str = "conflicting";
const SYMBOL_DEACTIVATE: &str = "deactivate";

const PROBLEM_ENCODING: &str = include_str!("encodings/problem.lp");
const META_PROBLEM_ENCODING: &str = include_str!("encodings/meta_problem.lp");

/// Finds `n_models` viable paths, where viability is here defined as satisfying
/// requirements and maximizing satisfaction of preferences expressed in the provided
/// policies.
///
/// If a `metapolicy` is provided, in the case of conflict detection (i.e. two
/// policies have an empty intersection of their solutions sets), it will be used
/// to try and override at least one policy for each conflict.
pub fn solve(
    pi: &ProblemInstance,
    policies: Vec<Policy>,
    issuers: Vec<Issuer>,
    metapolicy: Option<MetaPolicy>,
    n_models: u32,
) -> Result<Option<HashSet<Vec<Link>>>, ReasonerError> {
    let n_models_arg = format!("--models={}", n_models).to_string();
    let n_opt_arg = "--opt-mode=optN".to_string();

    log::info!("solving with {}", n_models_arg);

    let ctl_args = vec![n_models_arg, n_opt_arg];

    let mut fb = FactBase::new();
    pi.populate(&mut fb)
        .expect("failed at populating the fact base, this is probably an issue with the string identifiers in the links");

    if policies.is_empty() {
        let mut sols = HashSet::new();

        let mut ctl = control(ctl_args.clone()).expect("failed to create control handle");
        ctl.add_facts(&fb).expect("failed to add facts");
        ctl.add("base", &[], PROBLEM_ENCODING)
            .expect("failed to add base problem encoding");

        let parts = vec![Part::new("base", vec![]).expect("failed to create base parts")];
        ctl.ground(&parts).map_err(ReasonerError::AspError)?;

        for model in ctl.all_models().map_err(ReasonerError::AspError)? {
            let path = chosen_candidate(pi, model.symbols)?;
            log::debug!("Path found: {:?}", path);
            sols.insert(path);
        }

        return Ok(Some(sols));
    }

    // TODO: parallelize with rayon
    // solve search problem for every policy
    let mut results = HashMap::new();
    for pol in policies.iter() {
        let mut sols = HashSet::new();

        let mut ctl = control(ctl_args.clone()).expect("failed to create control handle");
        ctl.add_facts(&fb).expect("failed to add facts");
        ctl.add("base", &[], PROBLEM_ENCODING)
            .expect("failed to add base problem encoding");
        ctl.add("base", &[], pol.source())
            .map_err(ReasonerError::AspError)?;

        let parts = vec![Part::new("base", vec![]).expect("failed to create base parts")];
        ctl.ground(&parts).map_err(ReasonerError::AspError)?;

        if pol.source().contains("#maximize") || pol.source().contains("#minimize") {
            for model in ctl.optimal_models().map_err(ReasonerError::AspError)? {
                let path = chosen_candidate(pi, model.symbols)?;
                log::debug!("Path found: {:?}", path);
                sols.insert(path);
            }
        } else {
            for model in ctl.all_models().map_err(ReasonerError::AspError)? {
                let path = chosen_candidate(pi, model.symbols)?;
                log::debug!("Path found: {:?}", path);
                sols.insert(path);
            }
        }
        results.insert(pol.id(), sols);
    }

    let mpi = MetaProblemInstance {
        policies: &policies,
        issuers: &issuers,
        metadata: &pi.meta, // TODO: maybe it should be separate
        solutions: &results,
    };

    let mut meta_fb = FactBase::new();
    mpi.populate(&mut meta_fb)
        .map_err(ReasonerError::AspError)?;

    let mut meta_ctl =
        control(vec!["--models=0".to_string()]).expect("failed to create control handle");
    meta_ctl.add_facts(&meta_fb).expect("failed to add facts");
    meta_ctl
        .add("base", &[], META_PROBLEM_ENCODING)
        .map_err(ReasonerError::AspError)?;

    if let Some(mp) = metapolicy {
        meta_ctl
            .add("base", &[], mp.source())
            .map_err(ReasonerError::AspError)?;
        log::debug!("running with meta-policy:\n{}", mp.source());
    }

    let parts = vec![Part::new("base", vec![]).expect("failed to create base parts")];
    meta_ctl.ground(&parts).map_err(ReasonerError::AspError)?;

    let model = meta_ctl
        .all_models()
        .map_err(ReasonerError::AspError)?
        .next()
        .ok_or(ReasonerError::ConflictResolutionError)?;

    for atom in model.symbols.iter() {
        log::debug!("{}", atom.to_string());
        let atom_args = atom.arguments().expect("failed to extract atom args");
        if atom.name().expect("failed to extract atom name") == SYMBOL_DEACTIVATE
            && atom.is_positive().expect("failed to extract atom sign")
        {
            results.remove(
                atom_args
                    .first()
                    .expect("malformed active predicate")
                    .string()
                    .expect("failed to extract symbol string")
                    .parse::<uuid::Uuid>()
                    .expect("malformed policy id")
                    .as_ref(),
            );
        }
    }

    match results.iter().next() {
        None => Ok(None),
        Some((_, sols)) => {
            let mut out = sols.clone();
            for (_, sols) in results.iter() {
                out = out.intersection(sols).cloned().collect();
            }
            Ok(Some(out))
        }
    }
}

#[derive(Debug)]
pub enum ReasonerError {
    AspError(ClingoError),
    ConflictResolutionError,
    /// The model does not contain exactly one valid `chosen_path/1` atom
    /// (e.g. a policy injected extra atoms).
    MalformedModel,
}

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub enum MetadataValue {
    Boolean(bool),
    Numerical(i32), // Clingo only supports 32-bit integers
    Categorical(String),
}

/// A generic feture name - value pair
#[derive(Debug, Hash, PartialEq, Eq, Clone)]
pub struct Metadata {
    /// Name of the metadata feature
    pub name: String,
    /// Metadata value associated to a link (e.g., bandwidth)
    pub value: MetadataValue,
}

/// Represents a link between two AS nodes in the network.
/// It includes network interfaces and optional metadata.
#[derive(Debug, Eq, Clone)]
pub struct Link {
    /// Start AS node (i.e., in SCION an ISD-AS tuple)
    pub as_a: String,
    /// Start network interface (usually a number)
    pub if_a: String,
    /// End AS node (i.e., in SCION an ISD-AS tuple)
    pub as_b: String,
    /// End network interface (usually a number)
    pub if_b: String,
    /// Optional metadata associated to the link (e.g., bandwidth)
    pub meta: Option<Vec<Metadata>>,
}

/// Represents some global metadata for the path search that does not pertain
/// to a specific link but to some optional subject `subj`.
#[derive(Debug)]
pub struct GlobalMetadata {
    /// Name of the metadata feature
    pub name: String,
    /// Optional subject to which the feature pertains
    pub subj: Option<String>,
    /// Metadata associated to the subject or generic to the network (e.g. coordinates of a border router)
    pub value: MetadataValue,
}

/// Contains the data required to solve a path search problem.
/// It can populate a `clingo::FactBase` with the necessary atoms.
#[derive(Debug)]
pub struct ProblemInstance {
    /// Source AS node
    pub src: String,
    /// Destination AS node
    pub dst: String,
    /// Candidate paths discovered by the network stack; the solver only
    /// ever selects among these, so every solution is a real path
    pub paths: Vec<Vec<Link>>,
    /// Optional global metadata to inform the policies
    pub meta: Vec<GlobalMetadata>,
}

impl ProblemInstance {
    /// Add the ASP symbols for the base path search and provided metadata
    /// to a `clingo::FactBase` struct.
    fn populate(&self, fb: &mut FactBase) -> Result<(), ClingoError> {
        fb.insert(&Symbol::create_function(
            SYMBOL_SRC,
            &[Symbol::create_string(&self.src)?],
            true,
        )?);
        fb.insert(&Symbol::create_function(
            SYMBOL_DST,
            &[Symbol::create_string(&self.dst)?],
            true,
        )?);

        // links shared between candidates carry the same metadata atoms,
        // only emit them once
        let mut seen_links = HashSet::new();

        for (idx, path) in self.paths.iter().enumerate() {
            let path_symbol = Symbol::create_number(idx as i32);

            fb.insert(&Symbol::create_function(SYMBOL_PATH, &[path_symbol], true)?);

            for link in path.iter() {
                let args = vec![
                    Symbol::create_string(&link.as_a)?,
                    Symbol::create_string(&link.if_a)?,
                    Symbol::create_string(&link.as_b)?,
                    Symbol::create_string(&link.if_b)?,
                ];

                let mut in_path_args = vec![path_symbol];
                in_path_args.extend(args.iter().cloned());
                fb.insert(&Symbol::create_function(SYMBOL_IN_PATH, &in_path_args, true)?);

                if !seen_links.insert((
                    link.as_a.clone(),
                    link.if_a.clone(),
                    link.as_b.clone(),
                    link.if_b.clone(),
                )) {
                    continue;
                }

                if link.meta.is_none() {
                    continue;
                }

                for data in link.meta.as_ref().unwrap().iter() {
                    // coverage atom: lets policies distinguish "no data"
                    // from a negative verdict under closed-world semantics;
                    // always positive, even for false booleans
                    let mut coverage_args = vec![Symbol::create_string(&data.name)?];
                    coverage_args.extend(args.iter().cloned());
                    fb.insert(&Symbol::create_function(
                        SYMBOL_HAS_METADATA,
                        &coverage_args,
                        true,
                    )?);

                    match &data.value {
                        MetadataValue::Boolean(v) => {
                            fb.insert(&Symbol::create_function(&data.name, &args, *v)?)
                        }
                        MetadataValue::Numerical(v) => {
                            let mut new_args = args.clone();
                            new_args.push(Symbol::create_number(*v));
                            fb.insert(&Symbol::create_function(&data.name, &new_args, true)?)
                        }
                        MetadataValue::Categorical(v) => {
                            let mut new_args = args.clone();
                            new_args.push(Symbol::create_string(v)?);
                            fb.insert(&Symbol::create_function(&data.name, &new_args, true)?)
                        }
                    }
                }
            }
        }

        for data in self.meta.iter() {
            populate_global_metadata(fb, data)?;
        }

        Ok(())
    }
}

/// Contains the data required to resolve conflicts among policies.
/// It can populate a `clingo::FactBase` with the necessary atoms.
#[derive(Debug)]
pub struct MetaProblemInstance<'a> {
    policies: &'a Vec<Policy>,
    issuers: &'a Vec<Issuer>,
    metadata: &'a Vec<GlobalMetadata>,
    solutions: &'a HashMap<PolicyId, HashSet<Vec<Link>>>,
}

impl MetaProblemInstance<'_> {
    /// Add the ASP symbols for the currently published policies, issuers,
    /// and related metadata to a `clingo::FactBase` struct.
    fn populate(&self, fb: &mut FactBase) -> Result<(), ClingoError> {
        for issuer in self.issuers.iter() {
            fb.insert(&Symbol::create_function(
                SYMBOL_POWER,
                &[
                    Symbol::create_string(&issuer.id().to_string())?,
                    Symbol::create_number(issuer.rank()),
                ],
                true,
            )?);
        }

        for pol_a in self.policies.iter() {
            let pol_a_symbol = Symbol::create_string(&pol_a.id().to_string())?;

            match self.issuers.iter().find(|issuer| match pol_a.issuer_id() {
                None => false,
                Some(pol_issuer_id) => pol_issuer_id == issuer.id(),
            }) {
                None => {
                    fb.insert(&Symbol::create_function(
                        SYMBOL_ISSUED,
                        &[
                            Symbol::create_string(&DEFAULT_ISSUER.id().to_string())?,
                            pol_a_symbol,
                            Symbol::create_number(
                                pol_a
                                    .created_at()
                                    .timestamp()
                                    .try_into()
                                    .expect("we do not support i64 timestamps"),
                            ),
                        ],
                        true,
                    )?);
                    log::debug!(
                        "issued({}, {}, {})",
                        &DEFAULT_ISSUER.id().to_string(),
                        pol_a.id().to_string(),
                        pol_a.created_at().timestamp()
                    );
                }
                Some(issuer) => {
                    fb.insert(&Symbol::create_function(
                        SYMBOL_ISSUED,
                        &[
                            Symbol::create_string(&issuer.id().to_string())?,
                            pol_a_symbol,
                            Symbol::create_number(
                                pol_a
                                    .created_at()
                                    .timestamp()
                                    .try_into()
                                    .expect("we do not support i64 timestamps"),
                            ),
                        ],
                        true,
                    )?);
                    log::debug!(
                        "issued({}, {}, {})",
                        issuer.id().to_string(),
                        pol_a.id().to_string(),
                        pol_a.created_at().timestamp()
                    );
                }
            };

            for pol_b in self
                .policies
                .iter()
                .filter(|pol_b| pol_b.id() != pol_a.id())
            {
                let pol_b_symbol = Symbol::create_string(&pol_b.id().to_string())?;

                if self
                    .solutions
                    .get(&pol_a.id())
                    .unwrap()
                    .intersection(self.solutions.get(&pol_b.id()).unwrap())
                    .count()
                    == 0
                {
                    fb.insert(&Symbol::create_function(
                        SYMBOL_CONFLICTING,
                        &[pol_a_symbol, pol_b_symbol],
                        true,
                    )?);
                    log::debug!(
                        "conflicting({}, {})",
                        pol_a.id().to_string(),
                        pol_b.id().to_string()
                    );
                }
            }
        }

        for data in self.metadata.iter() {
            populate_global_metadata(fb, data)?;
        }

        Ok(())
    }
}

fn populate_global_metadata(fb: &mut FactBase, data: &GlobalMetadata) -> Result<(), ClingoError> {
    let mut args = match &data.subj {
        Some(subj) => vec![Symbol::create_string(subj)?],
        None => Vec::new(),
    };

    // coverage atom: lets policies distinguish "no data" from a negative
    // verdict under closed-world semantics; always positive, even for
    // false booleans
    let mut coverage_args = vec![Symbol::create_string(&data.name)?];
    coverage_args.extend(args.iter().cloned());
    fb.insert(&Symbol::create_function(
        SYMBOL_HAS_METADATA,
        &coverage_args,
        true,
    )?);

    match &data.value {
        MetadataValue::Boolean(v) => fb.insert(&Symbol::create_function(&data.name, &args, *v)?),
        MetadataValue::Numerical(v) => {
            args.push(Symbol::create_number(*v));
            fb.insert(&Symbol::create_function(&data.name, &args, true)?)
        }
        MetadataValue::Categorical(v) => {
            args.push(Symbol::create_string(v)?);
            fb.insert(&Symbol::create_function(&data.name, &args, true)?)
        }
    }

    Ok(())
}

/// Extracts the candidate path selected by a model. The problem encoding
/// guarantees exactly one `chosen_path/1` atom per model; anything else
/// means the model is malformed (e.g. a policy injected extra atoms).
fn chosen_candidate(pi: &ProblemInstance, symbols: Vec<Symbol>) -> Result<Vec<Link>, ReasonerError> {
    let mut chosen = None;
    for symbol in symbols.iter() {
        if symbol.name().map_err(ReasonerError::AspError)? != SYMBOL_CHOSEN_PATH {
            continue;
        }
        let args = symbol.arguments().map_err(ReasonerError::AspError)?;
        if args.len() != 1 || chosen.is_some() {
            return Err(ReasonerError::MalformedModel);
        }
        chosen = Some(args[0].number().map_err(ReasonerError::AspError)?);
    }

    let idx = chosen.ok_or(ReasonerError::MalformedModel)?;
    usize::try_from(idx)
        .ok()
        .and_then(|idx| pi.paths.get(idx))
        .cloned()
        .ok_or(ReasonerError::MalformedModel)
}

impl From<pb::Link> for Link {
    fn from(value: pb::Link) -> Self {
        Link {
            as_a: value.as_a,
            if_a: value.if_a,
            as_b: value.as_b,
            if_b: value.if_b,
            meta: None,
        }
    }
}

impl PartialEq for Link {
    fn eq(&self, other: &Self) -> bool {
        self.as_a == other.as_a
            && self.if_a == other.if_a
            && self.as_b == other.as_b
            && self.if_b == other.if_b
    }
}

impl Hash for Link {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_a.hash(state);
        self.if_a.hash(state);
        self.as_b.hash(state);
        self.if_b.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use core::time;
    use std::{thread, vec};

    use super::*;

    fn link(as_a: &str, if_a: &str, as_b: &str, if_b: &str) -> Link {
        Link {
            as_a: as_a.to_string(),
            if_a: if_a.to_string(),
            as_b: as_b.to_string(),
            if_b: if_b.to_string(),
            meta: None,
        }
    }

    fn get_simple_instance() -> ProblemInstance {
        ProblemInstance {
            src: "1".to_string(),
            dst: "4".to_string(),
            paths: vec![
                vec![link("1", "1", "2", "1"), link("2", "2", "4", "1")],
                vec![link("1", "3", "2", "3"), link("2", "2", "4", "1")],
                vec![link("1", "2", "3", "1"), link("3", "2", "4", "2")],
            ],
            meta: vec![],
        }
    }

    fn chosen_path_symbol(idx: i32) -> Symbol {
        Symbol::create_function(SYMBOL_CHOSEN_PATH, &[Symbol::create_number(idx)], true).unwrap()
    }

    #[test]
    fn test_chosen_candidate_returns_selected_path() {
        let pi = get_simple_instance();
        let path = chosen_candidate(&pi, vec![chosen_path_symbol(2)]).unwrap();
        assert_eq!(path, pi.paths[2]);
    }

    #[test]
    fn test_chosen_candidate_errors_without_selection() {
        let pi = get_simple_instance();
        match chosen_candidate(&pi, vec![]) {
            Err(ReasonerError::MalformedModel) => {}
            other => panic!("expected MalformedModel, got {:?}", other),
        }
    }

    #[test]
    fn test_chosen_candidate_errors_on_multiple_selections() {
        let pi = get_simple_instance();
        match chosen_candidate(&pi, vec![chosen_path_symbol(0), chosen_path_symbol(1)]) {
            Err(ReasonerError::MalformedModel) => {}
            other => panic!("expected MalformedModel, got {:?}", other),
        }
    }

    #[test]
    fn test_chosen_candidate_errors_on_out_of_range_index() {
        let pi = get_simple_instance();
        match chosen_candidate(&pi, vec![chosen_path_symbol(3)]) {
            Err(ReasonerError::MalformedModel) => {}
            other => panic!("expected MalformedModel, got {:?}", other),
        }
    }

    #[test]
    fn test_node_metadata_coverage_check() {
        let mut pi = get_simple_instance();
        // node "3" deliberately has no avg_psf entry
        pi.meta = vec![
            GlobalMetadata {
                name: "avg_psf".to_string(),
                subj: Some("1".to_string()),
                value: MetadataValue::Numerical(5),
            },
            GlobalMetadata {
                name: "avg_psf".to_string(),
                subj: Some("2".to_string()),
                value: MetadataValue::Numerical(5),
            },
        ];

        let pol = Policy::new(
            None,
            None,
            None,
            ":- chosen(AS, _, _, _), not has_metadata(\"avg_psf\", AS).".to_string(),
        )
        .unwrap();

        match solve(&pi, vec![pol], vec![], None, 10).unwrap() {
            None => panic!("could not find a path"),
            Some(paths) => {
                // only the two candidates through node "2" have full coverage
                assert_eq!(paths.len(), 2);
                for path in paths {
                    for link in path {
                        assert_ne!(link.as_a, "3");
                        assert_ne!(link.as_b, "3");
                    }
                }
            }
        }
    }

    #[test]
    fn test_link_metadata_coverage_check() {
        let mut pi = get_simple_instance();
        // only the links of the first candidate carry latency data
        for link in pi.paths[0].iter_mut() {
            link.meta = Some(vec![Metadata {
                name: "latency".to_string(),
                value: MetadataValue::Numerical(10),
            }]);
        }

        let pol = Policy::new(
            None,
            None,
            None,
            ":- chosen(X, XIF, Y, YIF), not has_metadata(\"latency\", X, XIF, Y, YIF).".to_string(),
        )
        .unwrap();

        match solve(&pi, vec![pol], vec![], None, 10).unwrap() {
            None => panic!("could not find a path"),
            Some(paths) => {
                assert_eq!(paths.len(), 1);
                for path in paths {
                    assert_eq!(path, pi.paths[0]);
                }
            }
        }
    }

    #[test]
    fn test_base_search() {
        let pi = get_simple_instance();
        match solve(&pi, vec![], vec![], None, 10).unwrap() {
            None => panic!("could not find a path"),
            Some(paths) => {
                // every candidate is viable without policies, and every
                // returned path is exactly one of the candidates
                assert_eq!(paths.len(), pi.paths.len());
                for path in paths {
                    assert!(pi.paths.contains(&path));
                }
            }
        }
    }

    #[test]
    fn test_hard_constraint() {
        let pi = get_simple_instance();
        let pol = Policy::new(None, None, None, ":- chosen(\"2\", _, _, _).".to_string()).unwrap();
        match solve(&pi, vec![pol], vec![], None, 10).unwrap() {
            None => panic!("could not find a path"),
            Some(paths) => {
                // only the candidate through node 3 satisfies the policy
                assert_eq!(paths.len(), 1);
                for path in paths {
                    assert!(pi.paths.contains(&path));
                    for link in path {
                        assert_ne!(link.as_a, "2");
                        assert_ne!(link.as_b, "2");
                    }
                }
            }
        }
    }

    #[test]
    fn test_soft_constraint() {
        let mut pi = get_simple_instance();
        pi.meta = vec![
            GlobalMetadata {
                name: "avg_psf".to_string(),
                subj: Some("1".to_string()),
                value: MetadataValue::Numerical(0),
            },
            GlobalMetadata {
                name: "avg_psf".to_string(),
                subj: Some("2".to_string()),
                value: MetadataValue::Numerical(5),
            },
            GlobalMetadata {
                name: "avg_psf".to_string(),
                subj: Some("3".to_string()),
                value: MetadataValue::Numerical(10),
            },
            GlobalMetadata {
                name: "avg_psf".to_string(),
                subj: Some("4".to_string()),
                value: MetadataValue::Numerical(0),
            },
        ];

        let pol = Policy::new(
            None,
            None,
            None,
            "
            total_avg_psf(TotAvgPsf) :-
            TotAvgPsf=#sum{AvgPsf: avg_psf(AS, AvgPsf),
            chosen(AS, _, _, _)}.

            #maximize { TotAvgPsf: total_avg_psf(TotAvgPsf) }.
            "
            .to_string(),
        )
        .unwrap();

        match solve(&pi, vec![pol], vec![], None, 10).unwrap() {
            None => panic!("could not find a path"),
            Some(paths) => {
                assert!(!paths.is_empty());
                for path in paths {
                    assert!(!path.is_empty());
                    for link in path {
                        assert_ne!(link.as_a, "2");
                        assert_ne!(link.as_b, "2");
                    }
                }
            }
        }
    }

    #[test]
    fn test_conflict_resolution_finds_error() {
        let pi = get_simple_instance();
        let pol_a =
            Policy::new(None, None, None, ":- chosen(\"2\", _, _, _).".to_string()).unwrap();
        let pol_b = Policy::new(
            None,
            None,
            None,
            ":- not chosen(\"2\", _, _, _).".to_string(),
        )
        .unwrap();
        solve(&pi, vec![pol_a, pol_b], vec![], None, 10).unwrap_err();
    }

    #[test]
    fn test_conflict_resolution_overrides() {
        env_logger::builder()
            .target(env_logger::Target::Stdout)
            .init();

        let pi = get_simple_instance();
        let pol_a = Policy::new(
            None,
            None,
            None,
            ":- not chosen(\"2\", _, _, _).".to_string(),
        )
        .unwrap();
        // ensure the two policies are not published at the same time and that
        // pol_b overrides pol_a, node 2 should never be chosen
        thread::sleep(time::Duration::from_secs(1));
        let pol_b =
            Policy::new(None, None, None, ":- chosen(\"2\", _, _, _).".to_string()).unwrap();
        let metapol = MetaPolicy::new(
            None,
            None,
            "
            overrides(P1, P2) :- conflicting(P1, P2),
                issued(_, P1, T1), issued(_, P2, T2),
                T1 > T2.
            "
            .to_string(),
        )
        .unwrap();
        match solve(&pi, vec![pol_a, pol_b], vec![], Some(metapol), 10).unwrap() {
            None => panic!("could not find a path"),
            Some(paths) => {
                assert!(!paths.is_empty());
                for path in paths {
                    assert!(!path.is_empty());
                    for link in path {
                        assert_ne!(link.as_a, "2");
                        assert_ne!(link.as_b, "2");
                    }
                }
            }
        }
    }
}
