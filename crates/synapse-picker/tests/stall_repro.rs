use synapse_picker::{Mode, Picker};

#[test]
fn cycling_every_piece_through_requested_and_back_to_missing_never_reports_complete() {
    let num_pieces = 2848usize;
    let mut picker = Picker::new(num_pieces, Mode::RarestFirst);

    for cycle in 0..5 {
        for idx in 0..num_pieces as u32 {
            picker.mark_requested(idx);
        }
        assert!(
            !picker.is_complete(),
            "cycle {cycle}: wrongly complete after marking every piece requested"
        );
        for idx in 0..num_pieces as u32 {
            picker.mark_missing(idx);
        }
        assert!(
            !picker.is_complete(),
            "cycle {cycle}: wrongly complete after marking every piece missing again"
        );
    }
}
