use std::path::{Component, Path};

use proptest::prelude::*;
use synapse_meta::{path_is_safe, MAX_COMPONENT_BYTES};

fn arb_safe_segment() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_-]{1,30}"
}

fn arb_control_char() -> impl Strategy<Value = char> {
    prop_oneof![
        (0u8..32u8).prop_map(|b| b as char),
        Just('\x7f'),
        Just('\u{202e}'), // RTL override
        Just('\u{2066}'), // LRI
    ]
}

proptest! {
    #[test]
    fn valid_alphanumeric_paths_are_always_safe(
        segments in prop::collection::vec(arb_safe_segment(), 1..6)
    ) {
        let joined = segments.join("/");
        let p = Path::new(&joined);
        prop_assert!(path_is_safe(p), "Expected safe path: {}", joined);
    }

    #[test]
    fn paths_with_traversal_components_are_never_safe(
        prefix in prop::collection::vec(arb_safe_segment(), 0..3),
        suffix in prop::collection::vec(arb_safe_segment(), 0..3),
    ) {
        let mut parts = prefix;
        parts.push("..".to_string());
        parts.extend(suffix);
        let joined = parts.join("/");
        prop_assert!(!path_is_safe(Path::new(&joined)), "Expected unsafe traversal path: {}", joined);
    }

    #[test]
    fn absolute_paths_are_never_safe(
        segments in prop::collection::vec(arb_safe_segment(), 1..4)
    ) {
        let joined = format!("/{}", segments.join("/"));
        prop_assert!(!path_is_safe(Path::new(&joined)), "Expected unsafe absolute path: {}", joined);
    }

    #[test]
    fn paths_with_control_or_bidi_characters_are_never_safe(
        seg_prefix in arb_safe_segment(),
        bad_char in arb_control_char(),
        seg_suffix in arb_safe_segment(),
    ) {
        let bad_seg = format!("{}{}{}", seg_prefix, bad_char, seg_suffix);
        prop_assert!(!path_is_safe(Path::new(&bad_seg)), "Expected unsafe control/bidi character");
    }

    #[test]
    fn overlong_components_are_never_safe(
        len in (MAX_COMPONENT_BYTES + 1)..600
    ) {
        let overlong = "a".repeat(len);
        prop_assert!(!path_is_safe(Path::new(&overlong)), "Expected overlong segment rejected");
    }

    #[test]
    fn safe_path_guarantees_strict_normal_components(path_str in ".*") {
        let p = Path::new(&path_str);
        if path_is_safe(p) {
            // Must contain at least one component
            let mut components = p.components().peekable();
            prop_assert!(components.peek().is_some());

            // Every component must strictly be Normal
            for comp in components {
                match comp {
                    Component::Normal(s) => {
                        let seg = s.to_str().unwrap();
                        prop_assert!(seg.len() <= MAX_COMPONENT_BYTES);
                        prop_assert!(!seg.is_empty());
                        prop_assert_ne!(seg, ".");
                        prop_assert_ne!(seg, "..");
                    }
                    _ => prop_assert!(false, "Non-normal component in safe path: {:?}", comp),
                }
            }
        }
    }
}
