//! Shared structured-filter arguments and their conversion into a [`Filter`].

use anyhow::{Context, Result};
use pcap_toolkit::filter::{
    Filter, IpNet, PortRange, TcpFlagsFilter, parse_datetime_ns, parse_flow_ids, parse_proto_list,
};

use crate::cli;

/// Common filter fields shared by the `sort`, `export`, and `replay` subcommands.
///
/// Implemented by each subcommand's argument struct so that [`build_filter`] can
/// be written once instead of once per subcommand.
pub trait FilterArgs {
    fn proto(&self) -> Option<&str>;
    fn src_ip(&self) -> &[String];
    fn dst_ip(&self) -> &[String];
    fn ip(&self) -> &[String];
    fn src_port(&self) -> &[String];
    fn dst_port(&self) -> &[String];
    fn port(&self) -> &[String];
    fn flow_id(&self) -> Option<&str>;
    fn from(&self) -> Option<&str>;
    fn to(&self) -> Option<&str>;
    fn tcp_flags(&self) -> Option<&str>;
    fn min_len(&self) -> Option<u32>;
    fn max_len(&self) -> Option<u32>;
    fn unidirectional(&self) -> bool;
    fn negate(&self) -> bool;
}

macro_rules! impl_filter_args {
    ($T:ty) => {
        impl FilterArgs for $T {
            fn proto(&self) -> Option<&str> {
                self.proto.as_deref()
            }
            fn src_ip(&self) -> &[String] {
                &self.src_ip
            }
            fn dst_ip(&self) -> &[String] {
                &self.dst_ip
            }
            fn ip(&self) -> &[String] {
                &self.ip
            }
            fn src_port(&self) -> &[String] {
                &self.src_port
            }
            fn dst_port(&self) -> &[String] {
                &self.dst_port
            }
            fn port(&self) -> &[String] {
                &self.port
            }
            fn flow_id(&self) -> Option<&str> {
                self.flow_id.as_deref()
            }
            fn from(&self) -> Option<&str> {
                self.from.as_deref()
            }
            fn to(&self) -> Option<&str> {
                self.to.as_deref()
            }
            fn tcp_flags(&self) -> Option<&str> {
                self.tcp_flags.as_deref()
            }
            fn min_len(&self) -> Option<u32> {
                self.min_len
            }
            fn max_len(&self) -> Option<u32> {
                self.max_len
            }
            fn unidirectional(&self) -> bool {
                self.unidirectional
            }
            fn negate(&self) -> bool {
                self.negate
            }
        }
    };
}

impl_filter_args!(cli::SortArgs);
impl_filter_args!(cli::export::ExportArgs);
impl_filter_args!(cli::replay::ReplayArgs);

/// Construct a [`Filter`] from any subcommand argument struct that implements [`FilterArgs`].
pub fn build_filter<A: FilterArgs>(args: &A) -> Result<Filter> {
    let mut filter = Filter {
        unidirectional: args.unidirectional(),
        negate: args.negate(),
        ..Filter::default()
    };

    if let Some(proto_str) = args.proto() {
        filter.protocols = parse_proto_list(proto_str)
            .with_context(|| format!("invalid --proto value '{proto_str}'"))?;
    }

    for text in args.src_ip() {
        filter
            .src_ips
            .push(IpNet::parse(text).with_context(|| format!("invalid --src-ip value '{text}'"))?);
    }
    for text in args.dst_ip() {
        filter
            .dst_ips
            .push(IpNet::parse(text).with_context(|| format!("invalid --dst-ip value '{text}'"))?);
    }
    for text in args.ip() {
        filter
            .ips
            .push(IpNet::parse(text).with_context(|| format!("invalid --ip value '{text}'"))?);
    }

    for text in args.src_port() {
        filter.src_ports.push(
            PortRange::parse(text).with_context(|| format!("invalid --src-port value '{text}'"))?,
        );
    }
    for text in args.dst_port() {
        filter.dst_ports.push(
            PortRange::parse(text).with_context(|| format!("invalid --dst-port value '{text}'"))?,
        );
    }
    for text in args.port() {
        filter.ports.push(
            PortRange::parse(text).with_context(|| format!("invalid --port value '{text}'"))?,
        );
    }

    if let Some(ids_str) = args.flow_id() {
        filter.flow_ids = parse_flow_ids(ids_str)
            .with_context(|| format!("invalid --flow-id value '{ids_str}'"))?
            .into_iter()
            .collect();
    }

    if let Some(from_str) = args.from() {
        filter.from_ns = Some(
            parse_datetime_ns(from_str)
                .with_context(|| format!("invalid --from value '{from_str}'"))?,
        );
    }
    if let Some(to_str) = args.to() {
        filter.to_ns = Some(
            parse_datetime_ns(to_str).with_context(|| format!("invalid --to value '{to_str}'"))?,
        );
    }

    if let Some(flags_str) = args.tcp_flags() {
        filter.tcp_flags = Some(
            TcpFlagsFilter::parse(flags_str)
                .with_context(|| format!("invalid --tcp-flags value '{flags_str}'"))?,
        );
    }

    filter.min_len = args.min_len();
    filter.max_len = args.max_len();

    Ok(filter)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_support::{export_args, replay_args, sort_args};

    #[test]
    fn test_build_filter_empty_yields_default() {
        let fs = build_filter(&sort_args()).unwrap();
        let fe = build_filter(&export_args()).unwrap();
        let fr = build_filter(&replay_args()).unwrap();
        assert!(fs.protocols.is_empty());
        assert!(fe.protocols.is_empty());
        assert!(fr.protocols.is_empty());
        assert!(!fs.negate);
        assert!(!fs.unidirectional);
    }

    #[test]
    fn test_build_filter_proto_parsed_for_all_arg_types() {
        let mut sa = sort_args();
        sa.proto = Some("tcp,udp".to_string());
        let mut ea = export_args();
        ea.proto = Some("tcp,udp".to_string());
        let mut ra = replay_args();
        ra.proto = Some("tcp,udp".to_string());

        for filter in [
            build_filter(&sa).unwrap(),
            build_filter(&ea).unwrap(),
            build_filter(&ra).unwrap(),
        ] {
            assert!(filter.protocols.contains(&6), "TCP missing");
            assert!(filter.protocols.contains(&17), "UDP missing");
        }
    }

    #[test]
    fn test_build_filter_src_dst_ip_parsed() {
        let mut sa = sort_args();
        sa.src_ip = vec!["10.0.0.0/8".to_string()];
        sa.dst_ip = vec!["192.168.1.1/32".to_string()];
        let filter = build_filter(&sa).unwrap();
        assert_eq!(filter.src_ips.len(), 1);
        assert_eq!(filter.dst_ips.len(), 1);
    }

    #[test]
    fn test_build_filter_either_endpoint_ip() {
        let mut sa = sort_args();
        sa.ip = vec!["172.16.0.0/12".to_string()];
        let filter = build_filter(&sa).unwrap();
        assert_eq!(filter.ips.len(), 1);
    }

    #[test]
    fn test_build_filter_ports_parsed() {
        let mut sa = sort_args();
        sa.src_port = vec!["1024-65535".to_string()];
        sa.dst_port = vec!["443".to_string()];
        sa.port = vec!["80".to_string()];
        let filter = build_filter(&sa).unwrap();
        assert_eq!(filter.src_ports.len(), 1);
        assert_eq!(filter.dst_ports.len(), 1);
        assert_eq!(filter.ports.len(), 1);
        assert_eq!(filter.dst_ports[0].start, 443);
        assert_eq!(filter.dst_ports[0].end, 443);
    }

    #[test]
    fn test_build_filter_flow_id_parsed() {
        let mut sa = sort_args();
        sa.flow_id = Some("deadbeef".to_string());
        let filter = build_filter(&sa).unwrap();
        assert_eq!(filter.flow_ids.len(), 1);
    }

    #[test]
    fn test_build_filter_time_range_parsed() {
        let mut sa = sort_args();
        sa.from = Some("1000".to_string()); // Unix epoch seconds
        sa.to = Some("2000".to_string());
        let filter = build_filter(&sa).unwrap();
        assert_eq!(filter.from_ns, Some(1_000 * 1_000_000_000));
        assert_eq!(filter.to_ns, Some(2_000 * 1_000_000_000));
    }

    #[test]
    fn test_build_filter_tcp_flags_parsed() {
        let mut sa = sort_args();
        sa.tcp_flags = Some("SYN".to_string());
        let filter = build_filter(&sa).unwrap();
        assert!(filter.tcp_flags.is_some());
    }

    #[test]
    fn test_build_filter_min_max_len() {
        let mut sa = sort_args();
        sa.min_len = Some(64);
        sa.max_len = Some(1500);
        let filter = build_filter(&sa).unwrap();
        assert_eq!(filter.min_len, Some(64));
        assert_eq!(filter.max_len, Some(1500));
    }

    #[test]
    fn test_build_filter_negate_and_unidirectional() {
        let mut sa = sort_args();
        sa.negate = true;
        sa.unidirectional = true;
        let filter = build_filter(&sa).unwrap();
        assert!(filter.negate);
        assert!(filter.unidirectional);
    }

    #[test]
    fn test_build_filter_invalid_proto_returns_error() {
        let mut sa = sort_args();
        sa.proto = Some("notaproto".to_string());
        assert!(build_filter(&sa).is_err());
    }

    #[test]
    fn test_build_filter_invalid_ip_returns_error() {
        let mut sa = sort_args();
        sa.src_ip = vec!["not.an.ip".to_string()];
        assert!(build_filter(&sa).is_err());
    }

    #[test]
    fn test_build_filter_invalid_port_returns_error() {
        let mut sa = sort_args();
        sa.dst_port = vec!["notaport".to_string()];
        assert!(build_filter(&sa).is_err());
    }

    /// Mutates a default `SortArgs` into an invalid state for one flag.
    type ArgMutator = fn(&mut cli::SortArgs);

    #[test]
    fn test_build_filter_invalid_values_name_the_flag() {
        let cases: [(ArgMutator, &str); 7] = [
            (|sa| sa.dst_ip = vec!["bad".into()], "--dst-ip"),
            (|sa| sa.ip = vec!["bad".into()], "--ip"),
            (|sa| sa.src_port = vec!["bad".into()], "--src-port"),
            (|sa| sa.port = vec!["bad".into()], "--port"),
            (|sa| sa.from = Some("not-a-date".into()), "--from"),
            (|sa| sa.to = Some("not-a-date".into()), "--to"),
            (|sa| sa.tcp_flags = Some("NOPE".into()), "--tcp-flags"),
        ];
        for (mutate, flag) in cases {
            let mut sa = sort_args();
            mutate(&mut sa);
            let err = build_filter(&sa).unwrap_err();
            assert!(
                format!("{err:#}").contains(flag),
                "error for {flag} should name the flag, got: {err:#}"
            );
        }
    }

    #[test]
    fn test_build_filter_all_arg_types_produce_identical_filter() {
        let (mut sa, mut ea, mut ra) = (sort_args(), export_args(), replay_args());
        for slot in [&mut sa.proto, &mut ea.proto, &mut ra.proto] {
            *slot = Some("tcp".to_string());
        }
        for slot in [&mut sa.src_ip, &mut ea.src_ip, &mut ra.src_ip] {
            *slot = vec!["10.0.0.0/8".to_string()];
        }
        for slot in [&mut sa.dst_port, &mut ea.dst_port, &mut ra.dst_port] {
            *slot = vec!["443".to_string()];
        }
        for slot in [&mut sa.min_len, &mut ea.min_len, &mut ra.min_len] {
            *slot = Some(64);
        }

        let fs = build_filter(&sa).unwrap();
        let fe = build_filter(&ea).unwrap();
        let fr = build_filter(&ra).unwrap();

        assert_eq!(fs.protocols, fe.protocols);
        assert_eq!(fs.protocols, fr.protocols);
        assert_eq!(fs.src_ips.len(), fe.src_ips.len());
        assert_eq!(fs.src_ips.len(), fr.src_ips.len());
        assert_eq!(fs.dst_ports[0].start, fe.dst_ports[0].start);
        assert_eq!(fs.dst_ports[0].start, fr.dst_ports[0].start);
        assert_eq!(fs.min_len, fe.min_len);
        assert_eq!(fs.min_len, fr.min_len);
    }
}
