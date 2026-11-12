//! The byte ranges of a file whose bytes are held locally.

use std::collections::BTreeMap;
use std::ops::Range;

/// A set of byte ranges, kept merged: no two ranges overlap or touch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RangeSet {
    /// Start to end, the end excluded.
    ranges: BTreeMap<u64, u64>,
}

impl RangeSet {
    /// A set that holds no bytes.
    pub(crate) fn new() -> Self {
        RangeSet::default()
    }

    /// Adds the bytes of `range`. An empty range adds nothing.
    pub(crate) fn insert(&mut self, range: Range<u64>) {
        if range.start >= range.end {
            return;
        }
        let (mut start, mut end) = (range.start, range.end);
        if let Some((&before, &before_end)) = self.ranges.range(..=start).next_back()
            && before_end >= start
        {
            start = before;
            end = end.max(before_end);
        }
        let absorbed: Vec<u64> = self
            .ranges
            .range(start..=end)
            .map(|(&next, _)| next)
            .collect();
        for next in absorbed {
            if let Some(next_end) = self.ranges.remove(&next) {
                end = end.max(next_end);
            }
        }
        self.ranges.insert(start, end);
    }

    /// Drops the bytes at `len` and past it.
    pub(crate) fn truncate(&mut self, len: u64) {
        let gone: Vec<u64> = self.ranges.range(len..).map(|(&start, _)| start).collect();
        for start in gone {
            self.ranges.remove(&start);
        }
        if let Some((_, end)) = self.ranges.range_mut(..len).next_back()
            && *end > len
        {
            *end = len;
        }
    }

    /// Whether the set holds no bytes.
    pub(crate) fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// One past the last byte held, 0 for an empty set.
    pub(crate) fn end(&self) -> u64 {
        self.ranges.values().next_back().copied().unwrap_or(0)
    }

    /// The ranges in order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = Range<u64>> + '_ {
        self.ranges.iter().map(|(&start, &end)| start..end)
    }

    /// Whether every byte below `len` is held.
    pub(crate) fn covers(&self, len: u64) -> bool {
        self.segments(0..len).iter().all(|(_, held)| *held)
    }

    /// Cuts `range` into consecutive pieces that are each held entirely or
    /// not at all, with whether they are held.
    pub(crate) fn segments(&self, range: Range<u64>) -> Vec<(Range<u64>, bool)> {
        let mut pieces = Vec::new();
        if range.start >= range.end {
            return pieces;
        }
        let mut at = range.start;
        let first = self
            .ranges
            .range(..=range.start)
            .next_back()
            .map_or(range.start, |(&start, _)| start);
        for (&start, &end) in self.ranges.range(first..) {
            if start >= range.end {
                break;
            }
            if end <= at {
                continue;
            }
            if start > at {
                pieces.push((at..start, false));
                at = start;
            }
            let stop = end.min(range.end);
            pieces.push((at..stop, true));
            at = stop;
            if at >= range.end {
                break;
            }
        }
        if at < range.end {
            pieces.push((at..range.end, false));
        }
        pieces
    }
}

impl FromIterator<Range<u64>> for RangeSet {
    fn from_iter<T: IntoIterator<Item = Range<u64>>>(ranges: T) -> Self {
        let mut set = RangeSet::new();
        for range in ranges {
            set.insert(range);
        }
        set
    }
}

#[cfg(test)]
#[expect(
    clippy::single_range_in_vec_init,
    reason = "a set of one range is a case under test"
)]
mod tests {
    use super::*;

    fn set(ranges: &[Range<u64>]) -> RangeSet {
        ranges.iter().cloned().collect()
    }

    fn held(set: &RangeSet) -> Vec<Range<u64>> {
        set.iter().collect()
    }

    #[test]
    fn disjoint_ranges_stay_apart_and_come_out_in_order() {
        let ranges = set(&[20..30, 0..5, 10..12]);
        assert_eq!(held(&ranges), [0..5, 10..12, 20..30]);
    }

    #[test]
    fn ranges_that_touch_or_overlap_merge() {
        assert_eq!(held(&set(&[0..5, 5..10])), [0..10]);
        assert_eq!(held(&set(&[5..10, 0..5])), [0..10]);
        assert_eq!(held(&set(&[0..6, 4..10])), [0..10]);
        assert_eq!(held(&set(&[0..2, 4..6, 8..10, 1..9])), [0..10]);
        assert_eq!(held(&set(&[2..8, 0..20])), [0..20]);
        assert_eq!(held(&set(&[0..20, 2..8])), [0..20]);
        assert_eq!(held(&set(&[0..2, 3..5])), [0..2, 3..5]);
    }

    #[test]
    fn an_empty_or_inverted_range_adds_nothing() {
        let mut ranges = set(&[0..5]);
        ranges.insert(7..7);
        let (high, low) = (9, 3);
        ranges.insert(high..low);
        assert_eq!(held(&ranges), [0..5]);
        assert_eq!(held(&RangeSet::new()), Vec::<Range<u64>>::new());
    }

    #[test]
    fn truncating_clips_the_range_that_straddles_the_length() {
        let mut ranges = set(&[0..10, 20..30, 40..50]);
        ranges.truncate(25);
        assert_eq!(held(&ranges), [0..10, 20..25]);
        ranges.truncate(20);
        assert_eq!(held(&ranges), [0..10]);
        ranges.truncate(5);
        assert_eq!(held(&ranges), [0..5]);
        ranges.truncate(0);
        assert_eq!(held(&ranges), Vec::<Range<u64>>::new());
        ranges.truncate(100);
        assert_eq!(ranges.end(), 0);
    }

    #[test]
    fn extending_after_a_truncate_marks_only_the_new_bytes() {
        let mut ranges = set(&[0..100]);
        ranges.truncate(40);
        ranges.insert(40..70);
        assert_eq!(held(&ranges), [0..70]);
        let mut gap = set(&[0..10]);
        gap.truncate(5);
        gap.insert(8..12);
        assert_eq!(held(&gap), [0..5, 8..12]);
    }

    #[test]
    fn the_end_is_that_of_the_last_range() {
        assert_eq!(RangeSet::new().end(), 0);
        assert_eq!(set(&[3..9, 20..21]).end(), 21);
    }

    #[test]
    fn segments_alternate_between_held_and_missing_bytes() {
        let ranges = set(&[10..20, 30..40]);
        assert_eq!(
            ranges.segments(0..50),
            [
                (0..10, false),
                (10..20, true),
                (20..30, false),
                (30..40, true),
                (40..50, false)
            ]
        );
        assert_eq!(ranges.segments(12..18), [(12..18, true)]);
        assert_eq!(
            ranges.segments(15..35),
            [(15..20, true), (20..30, false), (30..35, true)]
        );
        assert_eq!(ranges.segments(0..5), [(0..5, false)]);
        assert_eq!(ranges.segments(45..60), [(45..60, false)]);
        assert_eq!(ranges.segments(20..30), [(20..30, false)]);
        assert_eq!(ranges.segments(5..5), []);
        assert_eq!(RangeSet::new().segments(0..4), [(0..4, false)]);
    }

    #[test]
    fn segments_start_inside_a_range_that_began_earlier() {
        let ranges = set(&[0..100]);
        assert_eq!(ranges.segments(50..60), [(50..60, true)]);
        assert_eq!(
            ranges.segments(99..101),
            [(99..100, true), (100..101, false)]
        );
    }

    #[test]
    fn a_range_that_reaches_the_top_of_u64_merges() {
        let mut ranges = set(&[u64::MAX - 10..u64::MAX]);
        ranges.insert(u64::MAX - 20..u64::MAX - 5);
        assert_eq!(held(&ranges), [u64::MAX - 20..u64::MAX]);
    }
}
