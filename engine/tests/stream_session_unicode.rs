//! Rune counting under adversarial text.
//!
//! Offsets are Unicode scalar values. Every other length a host might reach for
//! disagrees, and a host whose counts disagree with the session's puts the two
//! out of step, which releases the wrong text. These tests pin the scale
//! against the encodings most likely to be confused with it.

#![cfg(feature = "streaming")]

use agent_control_spec::{
    SafetyLevel, SegmentOutcome, StreamEndReason, StreamSession, StreamSessionConfig,
    StreamSourceType, StreamSpan, StreamTrack,
};

fn session(level: SafetyLevel) -> StreamSession {
    StreamSession::new(StreamSessionConfig {
        safety_level: level,
        start_rune_offset: 0,
        request_tasks: vec!["t".to_string()],
        response_tasks: vec!["t".to_string()],
    })
    .expect("config is valid")
}

/// Text whose several plausible lengths all differ.
const SAMPLES: &[(&str, usize, usize, usize)] = &[
    // (text, runes, utf16 code units, bytes)
    ("hello", 5, 5, 5),
    ("héllo", 5, 5, 6),
    ("héllo 🌍", 7, 8, 11),
    ("🌍🌎🌏", 3, 6, 12),
    // A family emoji joined by zero width joiners. One grapheme, seven scalars.
    ("👨‍👩‍👧‍👦", 7, 11, 25),
    // Combining marks. Two scalars that render as one glyph.
    ("e\u{0301}", 2, 2, 3),
    // A precomposed character that looks identical to the line above.
    ("é", 1, 1, 2),
    // Devanagari with a combining vowel sign.
    ("\u{928}\u{92e}\u{938}\u{94d}\u{924}\u{947}", 6, 6, 18),
    // Right to left text.
    ("\u{645}\u{631}\u{62d}\u{628}\u{627}", 5, 5, 10),
    // A flag, which is two regional indicator scalars.
    ("🇯🇵", 2, 4, 8),
    // Astral plane CJK.
    ("𠜎𠜱𠝹", 3, 6, 12),
];

#[test]
fn observe_text_counts_scalar_values_not_code_units_or_bytes() {
    for (text, runes, utf16, bytes) in SAMPLES {
        assert_eq!(text.chars().count(), *runes, "sample {text:?} rune count");
        assert_eq!(
            text.encode_utf16().count(),
            *utf16,
            "sample {text:?} utf16 count"
        );
        assert_eq!(text.len(), *bytes, "sample {text:?} byte count");

        let mut s = session(SafetyLevel::Blocking);
        let end = s
            .observe_text(StreamSourceType::ModelGenerated, text)
            .expect("observe");
        assert_eq!(
            end, *runes as u32,
            "sample {text:?} advanced by {end} rather than its {runes} scalar values"
        );
    }
}

#[test]
fn a_stream_of_astral_text_settles_exactly() {
    // The whole point of a rune offset is that concatenating payloads and
    // summing their counts gives the same answer as counting the whole.
    let payloads = [
        "\u{1F30D}a",
        "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}",
        "\u{e9}",
        "\u{928}\u{92e}\u{938}\u{94d}\u{924}\u{947}",
        "\u{1F1EF}\u{1F1F5}z",
    ];
    let joined: String = payloads.concat();

    let mut s = session(SafetyLevel::Blocking);
    let mut running = 0u32;
    for payload in payloads {
        running = s
            .observe_text(StreamSourceType::ModelGenerated, payload)
            .expect("observe");
    }
    assert_eq!(
        running,
        joined.chars().count() as u32,
        "summing payload rune counts disagreed with counting the whole"
    );

    let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, running).expect("span");
    s.record_outcome("t", &span, SegmentOutcome::Cleared)
        .expect("clears");
    assert_eq!(s.advance(StreamTrack::Response), Some(running));
    assert_eq!(s.finish().reason, StreamEndReason::Complete);
}

#[test]
fn a_grapheme_split_across_payloads_still_accounts_exactly() {
    // A transport may split anywhere, including between the scalars of one
    // rendered glyph. The accounting counts scalars, so the split is invisible
    // to it, which is the property that makes offsets composable.
    let family = "👨‍👩‍👧‍👦";
    let scalars: Vec<char> = family.chars().collect();
    assert_eq!(scalars.len(), 7);

    for split in 1..scalars.len() {
        let head: String = scalars[..split].iter().collect();
        let tail: String = scalars[split..].iter().collect();

        let mut s = session(SafetyLevel::Blocking);
        s.observe_text(StreamSourceType::ModelGenerated, &head)
            .expect("observe head");
        let end = s
            .observe_text(StreamSourceType::ModelGenerated, &tail)
            .expect("observe tail");
        assert_eq!(
            end, 7,
            "splitting the sequence at scalar {split} changed the total"
        );

        let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, 7).expect("span");
        s.record_outcome("t", &span, SegmentOutcome::Cleared)
            .expect("clears");
        assert_eq!(s.finish().reason, StreamEndReason::Complete);
    }
}

#[test]
fn canonically_equivalent_text_is_counted_as_written_not_as_rendered() {
    // "é" precomposed and "e" plus a combining acute render identically and
    // have different scalar counts. The accounting counts what arrived, so a
    // host that normalises text before counting but after sending, or the
    // reverse, will disagree with the session. Pinned here so that hazard is
    // visible rather than discovered in production.
    let precomposed = "é";
    let decomposed = "e\u{0301}";
    assert_eq!(precomposed.chars().count(), 1);
    assert_eq!(decomposed.chars().count(), 2);

    let mut a = session(SafetyLevel::Blocking);
    let mut b = session(SafetyLevel::Blocking);
    assert_eq!(
        a.observe_text(StreamSourceType::ModelGenerated, precomposed),
        Ok(1)
    );
    assert_eq!(
        b.observe_text(StreamSourceType::ModelGenerated, decomposed),
        Ok(2)
    );
}

#[test]
fn empty_and_whitespace_payloads_move_nothing_and_break_nothing() {
    let mut s = session(SafetyLevel::Blocking);
    assert_eq!(s.observe_text(StreamSourceType::ModelGenerated, ""), Ok(0));
    assert_eq!(s.observe_text(StreamSourceType::ModelGenerated, ""), Ok(0));
    assert_eq!(s.observe_text(StreamSourceType::ModelGenerated, " "), Ok(1));
    assert_eq!(
        s.observe_text(StreamSourceType::ModelGenerated, "\u{200B}"),
        Ok(2),
        "a zero width space still occupies an offset"
    );
    let span = StreamSpan::new(StreamSourceType::ModelGenerated, 0, 2).expect("span");
    s.record_outcome("t", &span, SegmentOutcome::Cleared)
        .expect("clears");
    assert_eq!(s.finish().reason, StreamEndReason::Complete);
}

#[test]
fn a_lone_surrogate_cannot_be_constructed_in_rust_so_the_hazard_is_the_boundary() {
    // Rust strings cannot hold an unpaired surrogate, so this implementation
    // cannot produce one. A host on a UTF-16 platform can, and would count it
    // as one code unit where this counts a replacement character or refuses
    // the input. Recorded so the boundary is documented rather than assumed.
    let replacement = char::REPLACEMENT_CHARACTER.to_string();
    assert_eq!(replacement.chars().count(), 1);
    let mut s = session(SafetyLevel::Blocking);
    assert_eq!(
        s.observe_text(StreamSourceType::ModelGenerated, &replacement),
        Ok(1)
    );
}
