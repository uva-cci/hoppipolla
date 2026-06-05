use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use lazy_static::lazy_static;
use tokio::sync::{Mutex, RwLock};
use tonic::{transport::Channel, Request, Response, Status};

use crate::db::PolicyDb;
use crate::entities::{Issuer, IssuerId, MetaPolicy, Policy, PolicyId};
use crate::nip_proxy::nip_proxy_client::NipProxyClient;
use crate::nip_proxy::{self as nippb};
use crate::path_analyzer::path_analyzer_client::PathAnalyzerClient;
use crate::policy_manager::policy_manager_server::PolicyManager;
use crate::policy_manager::{self as pb};
use crate::reasoner::{self, ReasonerError};

pub struct Service {
    config: crate::Config,
    db: PolicyDb,
    nip_proxy: Option<NipProxyClient<Channel>>,
}

struct ClientHandle {
    stale: bool,
    addr: String,
    chan: Option<PathAnalyzerClient<Channel>>,
}

impl ClientHandle {
    async fn refresh(&mut self) -> Result<(), Status> {
        if self.stale {
            if self.chan.is_none() {
                self.chan = Some(
                    PathAnalyzerClient::connect(format!("grpc://{}", self.addr.clone()))
                        .await
                        .map_err(|e| {
                            log::error!("PathAnalyzerClient::connect({}): {}", self.addr, e);
                            Status::unknown(e.to_string())
                        })?,
                );
            }
            self.chan.clone().unwrap().refresh(Request::new(())).await?;
            self.stale = false;
        }
        Ok(())
    }
}

lazy_static! {
    static ref CLIENTS: Mutex<Vec<ClientHandle>> = Mutex::new(Vec::default());
    static ref META_POLICY: Arc<RwLock<Option<MetaPolicy>>> = Arc::new(RwLock::new(None));
    static ref POLICIES: Arc<RwLock<HashMap<PolicyId, Policy>>> =
        Arc::new(RwLock::new(HashMap::new()));
    static ref ISSUERS: Arc<RwLock<HashMap<IssuerId, Issuer>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// Retries client refresh RPCs until they are not stale anymore
pub async fn run_broadcast_daemon() -> Result<(), tonic::transport::Error> {
    loop {
        let mut clients = CLIENTS.lock().await;
        for client in clients.iter_mut() {
            if client.refresh().await.is_err() {
                log::error!("failed to refresh client {}", client.addr)
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

impl Service {
    async fn refresh(&self) -> Result<(), Status> {
        let mut clients = CLIENTS.lock().await;

        // TODO(andrea): parallelize
        for client in clients.iter_mut() {
            client.stale = true;
            if let Err(e) = client.refresh().await {
                return Err(Status::internal(e.message()));
            }
        }

        Ok(())
    }

    pub async fn with_config(config: crate::Config) -> Self {
        let db = PolicyDb::new(&config.db_uri, config.db_max_conns).await;

        let mut policies = POLICIES.write().await;
        *policies = db
            .load_policies()
            .await
            .into_iter()
            .map(|p| (p.id(), p))
            .collect::<HashMap<_, _>>();

        let mut issuers = ISSUERS.write().await;
        *issuers = db
            .load_issuers()
            .await
            .into_iter()
            .map(|i| (i.id(), i))
            .collect::<HashMap<_, _>>();

        let mut meta_policy = META_POLICY.write().await;
        *meta_policy = db.load_meta_policy().await;

        Self {
            config,
            db,
            nip_proxy: None, // needs to be initialized at startup
        }
    }

    pub async fn init(&mut self) -> Result<(), Status> {
        self.nip_proxy = Some(
            NipProxyClient::connect(format!("grpc://{}", self.config.nip_proxy_addr))
                .await
                .map_err(|e| {
                    log::error!(
                        "failed to init nip proxy client at '{}': {}",
                        self.config.nip_proxy_addr,
                        e,
                    );
                    Status::unknown(e.to_string())
                })?,
        );

        Ok(())
    }
}

/// Converts the value union of a NIP metadata entry into a reasoner value,
/// requiring exactly one of the fields to be set. Malformed entries degrade
/// to a failed RPC instead of crashing the service.
fn metadata_value(
    name: &str,
    value_bool: Option<bool>,
    value_int32: Option<i32>,
    value_string: &Option<String>,
) -> Result<reasoner::MetadataValue, Status> {
    match (value_bool, value_int32, value_string) {
        (Some(v), None, None) => Ok(reasoner::MetadataValue::Boolean(v)),
        (None, Some(v), None) => Ok(reasoner::MetadataValue::Numerical(v)),
        (None, None, Some(v)) => Ok(reasoner::MetadataValue::Categorical(v.to_owned())),
        _ => Err(Status::invalid_argument(format!(
            "nip proxy returned metadata '{}' without exactly one value set",
            name
        ))),
    }
}

#[tonic::async_trait]
impl PolicyManager for Service {
    async fn create_policy(
        &self,
        request: tonic::Request<pb::CreatePolicyRequest>,
    ) -> std::result::Result<Response<pb::CreatePolicyResponse>, Status> {
        let req = request.get_ref().clone();
        let mut res = pb::CreatePolicyResponse::default();

        let issuer_id = match req.issuer_id {
            None => None,
            Some(id) => Some(
                id.parse::<IssuerId>()
                    .map_err(|_| Status::invalid_argument("invalid issuer id"))?,
            ),
        };

        let p = Policy::new(issuer_id, req.title, req.description, req.source)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let mut tx = self.db.tx().await;

        let mut policies = POLICIES.write().await;
        policies.insert(p.id(), p.clone());

        self.db
            .insert_policy(&mut *tx, &p)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        res.policy = Some((&p).into());

        // NOTE: maybe we should not fail on client refresh
        self.refresh().await?;

        tx.commit()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(res))
    }

    async fn read_policy(
        &self,
        req: tonic::Request<pb::ReadPolicyRequest>,
    ) -> std::result::Result<Response<pb::ReadPolicyResponse>, Status> {
        let mut res = pb::ReadPolicyResponse::default();

        let id = req
            .get_ref()
            .id
            .parse::<PolicyId>()
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        if let Some(p) = POLICIES.read().await.get(&id) {
            res.policy = Some(p.into());
        } else {
            return Err(Status::not_found("no policy with specified id"));
        }

        Ok(Response::new(res))
    }

    async fn update_policy(
        &self,
        req: tonic::Request<pb::UpdatePolicyRequest>,
    ) -> std::result::Result<Response<pb::UpdatePolicyResponse>, Status> {
        let req = req.get_ref();
        let mut res = pb::UpdatePolicyResponse::default();

        let id = req
            .id
            .parse::<PolicyId>()
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let mut policies = POLICIES.write().await;

        let v = policies.get_mut(&id);
        if v.is_none() {
            return Err(Status::not_found("no policy with specified id"));
        }

        let mut tx = self.db.tx().await;

        let p = v.unwrap();
        if req.title.is_some() {
            p.set_title(req.title.clone());
        }
        if req.description.is_some() {
            p.set_description(req.description.clone());
        }
        if let Some(source) = req.statements.clone() {
            p.set_source(source)
                .map_err(|e| Status::invalid_argument(e.to_string()))?;
        }

        self.db
            .update_policy(&mut *tx, p)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        // NOTE: maybe we should not fail on client refresh
        self.refresh().await?;

        tx.commit()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        res.policy = Some((&*p).into());

        Ok(Response::new(res))
    }

    async fn delete_policy(
        &self,
        req: tonic::Request<pb::DeletePolicyRequest>,
    ) -> std::result::Result<Response<()>, Status> {
        let id = &req
            .get_ref()
            .id
            .parse::<PolicyId>()
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let mut tx = self.db.tx().await;

        let op = self
            .db
            .delete_policy(&mut *tx, id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        if op.rows_affected() == 0 {
            return Err(Status::not_found("no policy with specified id"));
        }

        POLICIES.write().await.remove(id);

        // NOTE: maybe we should not fail on client refresh
        self.refresh().await?;

        tx.commit()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(()))
    }

    async fn list_policies(
        &self,
        _: tonic::Request<pb::ListPoliciesRequest>,
    ) -> std::result::Result<Response<pb::ListPoliciesResponse>, Status> {
        let mut res = pb::ListPoliciesResponse::default();
        let policies = POLICIES.read().await;
        res.policies = policies.values().map(Into::into).collect();
        Ok(Response::new(res))
    }

    async fn find_paths(
        &self,
        req: tonic::Request<pb::FindPathsRequest>,
    ) -> std::result::Result<Response<pb::FindPathsResponse>, Status> {
        let req = req.get_ref().clone();
        let mut res = pb::FindPathsResponse::default();

        let policies = POLICIES.read().await.values().cloned().collect();
        let issuers = ISSUERS.read().await.values().cloned().collect();
        let meta_policy = META_POLICY.read().await.clone();

        // flatten the candidate paths into a deduplicated link topology for
        // the metadata lookup; links shared between candidates only need to
        // be resolved once
        let mut seen_links = HashSet::new();
        let topology = req
            .paths
            .iter()
            .flat_map(|path| path.links.iter())
            .filter(|link| {
                seen_links.insert((
                    link.as_a.clone(),
                    link.if_a.clone(),
                    link.as_b.clone(),
                    link.if_b.clone(),
                ))
            })
            .map(|link| nippb::Link {
                as_a: link.as_a.clone(),
                if_a: link.if_a.clone(),
                as_b: link.as_b.clone(),
                if_b: link.if_b.clone(),
            })
            .collect();

        let nip_res = self
            .nip_proxy
            .clone() // FIXME: might be undesireable behavior
            .expect("nip proxy client not initialized")
            .get_metadata(nippb::GetMetadataRequest {
                src: req.src.clone(),
                dst: req.dst.clone(),
                topology,
            })
            .await?;

        let paths = req
            .paths
            .iter()
            .map(|path| {
                path.links
                    .iter()
                    .map(|link| {
                        let meta = nip_res
                            .get_ref()
                            .link_info
                            .iter()
                            .filter(|info| {
                                info.link.as_ref().is_some_and(|info_link| {
                                    info_link.as_a == link.as_a
                                        && info_link.if_a == link.if_a
                                        && info_link.as_b == link.as_b
                                        && info_link.if_b == link.if_b
                                })
                            })
                            .map(|info| {
                                Ok(reasoner::Metadata {
                                    name: info.name.to_owned(),
                                    value: metadata_value(
                                        &info.name,
                                        info.value_bool,
                                        info.value_int32,
                                        &info.value_string,
                                    )?,
                                })
                            })
                            .collect::<Result<Vec<_>, Status>>()?;

                        Ok(reasoner::Link {
                            as_a: link.as_a.to_owned(),
                            if_a: link.if_a.to_owned(),
                            as_b: link.as_b.to_owned(),
                            if_b: link.if_b.to_owned(),
                            meta: Some(meta),
                        })
                    })
                    .collect::<Result<Vec<_>, Status>>()
            })
            .collect::<Result<Vec<_>, Status>>()?;

        let meta = nip_res
            .get_ref()
            .node_info
            .iter()
            .map(|info| {
                Ok(reasoner::GlobalMetadata {
                    name: info.name.to_owned(),
                    subj: Some(info.node.to_owned()),
                    value: metadata_value(
                        &info.name,
                        info.value_bool,
                        info.value_int32,
                        &info.value_string,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;

        let pi = reasoner::ProblemInstance {
            src: req.src.to_owned(),
            dst: req.dst.to_owned(),
            paths,
            meta,
        };

        // log::debug!("{:?}", pi);

        let solution = reasoner::solve(&pi, policies, issuers, meta_policy, self.config.n_models)
            .map_err(|err| match err {
            ReasonerError::AspError(e) => Status::internal(e.to_string()),
            ReasonerError::ConflictResolutionError => {
                Status::aborted("failed to solve conflict".to_string())
            }
            ReasonerError::MalformedModel => Status::internal(
                "solver produced a model without exactly one chosen candidate path".to_string(),
            ),
        })?;

        if let Some(paths) = solution {
            res.paths = paths
                .iter()
                .map(|p| pb::Path {
                    links: p
                        .iter()
                        .map(|link| pb::Link {
                            as_a: link.as_a.to_owned(),
                            if_a: link.if_a.to_owned(),
                            as_b: link.as_b.to_owned(),
                            if_b: link.if_b.to_owned(),
                        })
                        .collect(),
                })
                .collect();
        }

        Ok(Response::new(res))
    }

    async fn register_issuer(
        &self,
        request: tonic::Request<pb::RegisterIssuerRequest>,
    ) -> std::result::Result<Response<pb::RegisterIssuerResponse>, Status> {
        let req = request.get_ref().clone();
        let mut res = pb::RegisterIssuerResponse::default();

        let issuer = Issuer::new(req.name, req.rank, req.description);

        let mut tx = self.db.tx().await;

        let mut issuers = ISSUERS.write().await;
        issuers.insert(issuer.id(), issuer.clone());

        self.db
            .insert_issuer(&mut *tx, &issuer)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        res.issuer = Some((&issuer).into());

        // NOTE: maybe we should not fail on client refresh
        self.refresh().await?;

        tx.commit()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(res))
    }

    async fn subscribe_path_analyzer(
        &self,
        request: Request<pb::SubscribePathAnalyzerRequest>,
    ) -> Result<Response<()>, Status> {
        let addr = request.get_ref().clone().broadcast_addr;

        log::info!("Registered client at {}", request.get_ref().broadcast_addr);

        let mut clients = CLIENTS.lock().await;
        let client = ClientHandle {
            addr,
            chan: None,
            stale: false,
        };
        clients.push(client);

        Ok(Response::new(()))
    }

    async fn reset_policies(&self, _: Request<()>) -> Result<Response<()>, Status> {
        let mut tx = self.db.tx().await;

        self.db
            .reset_policies(&mut *tx)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        self.db
            .reset_meta_policies(&mut *tx)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        POLICIES.write().await.clear();
        *META_POLICY.write().await = None;

        Ok(Response::new(()))
    }

    async fn set_meta_policy(
        &self,
        request: Request<pb::SetMetaPolicyRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.get_ref().clone();

        let mp = MetaPolicy::new(req.title, req.description, req.source)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let mut tx = self.db.tx().await;

        self.db
            .insert_metapolicy(&mut *tx, &mp)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let mut meta_policy = META_POLICY.write().await;
        log::debug!("new meta-policy:\n{}", mp.source());
        *meta_policy = Some(mp);

        Ok(Response::new(()))
    }
}
