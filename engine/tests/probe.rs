#[test]
fn probe_target_root_parses() {
    let p = agent_control_spec::JsonPath::parse("$target.text");
    assert!(p.is_ok(), "{:?}", p.err());
    let a = agent_control_spec::JsonPath::parse_with_snapshot_alias("$target.text");
    assert!(a.is_ok(), "{:?}", a.err());
}
