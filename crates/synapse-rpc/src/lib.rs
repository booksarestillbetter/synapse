pub mod event_bus;
pub mod http_api;
pub mod metrics;
pub mod proto;
pub mod service;
pub mod swagger;
pub mod url_fetcher;
pub mod web;

/// Maximum gRPC message size (16 MiB) shared across server and client transports so
/// multi-megabyte `.torrent` add/export RPCs fit without hitting Tonic's 4 MiB default.
pub const MAX_GRPC_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

pub use event_bus::EventBus;
pub use http_api::{
    create_http_router, create_http_router_all, create_http_router_full,
    create_http_router_with_auth, create_http_router_with_options,
};
pub use metrics::{render_prometheus_metrics, PrometheusSnapshot};
pub use proto::v2 as proto_v2;
pub use service::SynapseService;
pub use swagger::{get_swagger_ui_html, OPENAPI_JSON};
pub use url_fetcher::{fetch_or_parse_torrent, FetchTorrentError};
