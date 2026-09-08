pub mod event_bus;
pub mod http_api;
pub mod metrics;
pub mod proto;
pub mod service;
pub mod swagger;
pub mod url_fetcher;

pub use event_bus::EventBus;
pub use http_api::{create_http_router, create_http_router_full, create_http_router_with_auth};
pub use metrics::{render_prometheus_metrics, PrometheusSnapshot};
pub use proto::v2 as proto_v2;
pub use service::SynapseService;
pub use swagger::{get_swagger_ui_html, OPENAPI_JSON};
pub use url_fetcher::{fetch_or_parse_torrent, FetchTorrentError};
