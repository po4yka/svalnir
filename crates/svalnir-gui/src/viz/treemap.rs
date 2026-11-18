//! Squarified treemap on an integer lattice of cells.

/// A rectangle of lattice cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CellRect {
    /// Left cell.
    pub x: u16,
    /// Top cell.
    pub y: u16,
    /// Width in cells.
    pub w: u16,
    /// Height in cells.
    pub h: u16,
}

impl CellRect {
    /// Creates a rectangle.
    #[must_use]
    pub const fn new(x: u16, y: u16, w: u16, h: u16) -> Self {
        Self { x, y, w, h }
    }

    /// The number of cells.
    #[must_use]
    pub const fn area(self) -> u32 {
        self.w as u32 * self.h as u32
    }

    /// Whether the rectangle has no cell.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.w == 0 || self.h == 0
    }

    /// Whether the cell `(x, y)` lies inside.
    #[must_use]
    pub const fn contains(self, x: u16, y: u16) -> bool {
        x >= self.x && y >= self.y && x - self.x < self.w && y - self.y < self.h
    }

    /// The rectangle without its last column and last row, so that
    /// neighbours keep one cell between their outlines. A rectangle that is
    /// one cell wide or high keeps that side.
    #[must_use]
    pub const fn gapped(self) -> Self {
        Self {
            x: self.x,
            y: self.y,
            w: if self.w > 1 { self.w - 1 } else { self.w },
            h: if self.h > 1 { self.h - 1 } else { self.h },
        }
    }
}

/// Converts a weight to a float for the aspect ratios; a loss of low bits is
/// harmless there.
#[expect(clippy::cast_precision_loss, reason = "ratios need no exact bits")]
const fn ratio_f64(value: u128) -> f64 {
    value as f64
}

/// The worst aspect ratio of a row of `areas` laid along a side of `side`.
fn worst_ratio(areas: &[f64], side: f64) -> f64 {
    let sum: f64 = areas.iter().sum();
    if sum <= 0.0 || side <= 0.0 {
        return f64::MAX;
    }
    let max: f64 = areas.iter().copied().fold(0.0, f64::max);
    let min: f64 = areas.iter().copied().fold(f64::MAX, f64::min);
    let s2: f64 = side * side;
    ((s2 * max) / (sum * sum)).max((sum * sum) / (s2 * min))
}

/// Rounds `side * part / whole` to the nearest integer.
fn scaled(side: u32, part: u128, whole: u128) -> u32 {
    if whole == 0 {
        return 0;
    }
    let value: u128 = (u128::from(side) * part * 2 + whole) / (whole * 2);
    u32::try_from(value).unwrap_or(side).min(side)
}

/// Lays `weights` (largest first) out in `area` by the squarified algorithm.
///
/// Each rectangle has integer cell coordinates. The rectangles do not overlap
/// and tile `area` exactly when every weight is above zero. A zero weight gets
/// an empty rectangle. The order of the result is the order of the input. A
/// weight so small that it rounds to less than one cell also gets an empty
/// rectangle, and its cells go to a neighbour.
#[must_use]
pub fn squarify(weights: &[u64], area: CellRect) -> Vec<CellRect> {
    let mut out: Vec<CellRect> = vec![CellRect::new(area.x, area.y, 0, 0); weights.len()];
    let order: Vec<usize> = (0..weights.len()).filter(|&i| weights[i] > 0).collect();
    let mut rest_weight: u128 = order.iter().map(|&i| u128::from(weights[i])).sum();
    let mut rem: CellRect = area;
    let mut next: usize = 0;
    while next < order.len() && !rem.is_empty() {
        let wide: bool = rem.w >= rem.h;
        // The row stacks along the long side; its items split the short side.
        let short: u32 = u32::from(if wide { rem.h } else { rem.w });
        let long: u32 = u32::from(if wide { rem.w } else { rem.h });
        let rem_area: f64 = f64::from(short) * f64::from(long);
        let unit: f64 = rem_area / ratio_f64(rest_weight);
        let mut end: usize = next + 1;
        let mut areas: Vec<f64> = vec![ratio_f64(u128::from(weights[order[next]])) * unit];
        let mut best: f64 = worst_ratio(&areas, f64::from(short));
        while end < order.len() {
            areas.push(ratio_f64(u128::from(weights[order[end]])) * unit);
            let ratio: f64 = worst_ratio(&areas, f64::from(short));
            if ratio > best {
                areas.pop();
                break;
            }
            best = ratio;
            end += 1;
        }
        let row: &[usize] = &order[next..end];
        let row_weight: u128 = row.iter().map(|&i| u128::from(weights[i])).sum();
        let last_row: bool = end == order.len();
        let thickness: u32 = if last_row {
            long
        } else {
            scaled(long, row_weight, rest_weight).clamp(1, long)
        };
        let mut offset: u32 = 0;
        let mut cumulative: u128 = 0;
        for &i in row {
            cumulative += u128::from(weights[i]);
            let edge: u32 = scaled(short, cumulative, row_weight);
            let (a, b): (u32, u32) = (offset, edge);
            offset = edge;
            let (t, s0, s): (u16, u16, u16) = (
                u16::try_from(thickness).unwrap_or(u16::MAX),
                u16::try_from(a).unwrap_or(u16::MAX),
                u16::try_from(b - a).unwrap_or(u16::MAX),
            );
            out[i] = if wide {
                CellRect::new(rem.x, rem.y + s0, t, s)
            } else {
                CellRect::new(rem.x + s0, rem.y, s, t)
            };
        }
        let t16: u16 = u16::try_from(thickness).unwrap_or(u16::MAX);
        rem = if wide {
            CellRect::new(rem.x + t16, rem.y, rem.w - t16, rem.h)
        } else {
            CellRect::new(rem.x, rem.y + t16, rem.w, rem.h - t16)
        };
        rest_weight -= row_weight;
        next = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlap(a: CellRect, b: CellRect) -> bool {
        !a.is_empty()
            && !b.is_empty()
            && a.x < b.x + b.w
            && b.x < a.x + a.w
            && a.y < b.y + b.h
            && b.y < a.y + a.h
    }

    fn inside(r: CellRect, area: CellRect) -> bool {
        r.is_empty()
            || (r.x >= area.x
                && r.y >= area.y
                && r.x + r.w <= area.x + area.w
                && r.y + r.h <= area.y + area.h)
    }

    const WEIGHTS: [u64; 8] = [720, 480, 300, 250, 120, 80, 40, 10];

    #[test]
    fn tiles_the_area_exactly() {
        let area = CellRect::new(3, 2, 60, 40);
        let rects = squarify(&WEIGHTS, area);
        assert_eq!(rects.len(), WEIGHTS.len());
        let sum: u32 = rects.iter().map(|r| r.area()).sum();
        assert_eq!(sum, area.area());
        assert!(rects.iter().all(|&r| inside(r, area)));
    }

    #[test]
    fn rectangles_do_not_overlap() {
        let area = CellRect::new(0, 0, 61, 37);
        let rects = squarify(&WEIGHTS, area);
        for (i, a) in rects.iter().enumerate() {
            for b in &rects[i + 1..] {
                assert!(!overlap(*a, *b), "{a:?} overlaps {b:?}");
            }
        }
    }

    #[test]
    fn areas_follow_the_weights_within_rounding() {
        let area = CellRect::new(0, 0, 60, 40);
        let rects = squarify(&WEIGHTS, area);
        let slack: u32 = u32::from(area.w) + u32::from(area.h);
        for pair in rects.windows(2) {
            assert!(pair[0].area() + slack >= pair[1].area(), "{pair:?}");
        }
        let total: u64 = WEIGHTS.iter().sum();
        let ideal: f64 = f64::from(area.area()) * ratio_f64(u128::from(WEIGHTS[0]))
            / ratio_f64(u128::from(total));
        assert!((f64::from(rects[0].area()) - ideal).abs() <= f64::from(slack));
    }

    #[test]
    fn one_weight_fills_the_area() {
        let area = CellRect::new(5, 5, 20, 10);
        assert_eq!(squarify(&[9], area), vec![area]);
    }

    #[test]
    fn zero_weights_get_empty_rectangles_and_the_rest_tiles() {
        let area = CellRect::new(0, 0, 30, 20);
        let rects = squarify(&[50, 0, 30, 0], area);
        assert!(rects[1].is_empty() && rects[3].is_empty());
        let sum: u32 = rects.iter().map(|r| r.area()).sum();
        assert_eq!(sum, area.area());
        assert!(squarify(&[0, 0], area).iter().all(|r| r.is_empty()));
        assert_eq!(squarify(&[], area), Vec::<CellRect>::new());
    }

    #[test]
    fn a_single_row_area_splits_along_the_row() {
        let area = CellRect::new(0, 7, 40, 1);
        let rects = squarify(&[20, 10, 10], area);
        assert!(rects.iter().all(|r| r.h == 1 && r.y == 7));
        let sum: u32 = rects.iter().map(|r| r.area()).sum();
        assert_eq!(sum, 40);
        assert_eq!(rects[0].w, 20);
    }

    #[test]
    fn gapped_keeps_a_one_cell_side() {
        assert_eq!(
            CellRect::new(0, 0, 4, 1).gapped(),
            CellRect::new(0, 0, 3, 1)
        );
    }
}
