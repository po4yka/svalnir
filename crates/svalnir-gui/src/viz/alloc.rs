//! Pure cell allocation for the cell charts.

/// The state of one cell of a chart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellState {
    /// Not filled: drawn in the `border` color.
    Empty,
    /// Filled with the color of the cell.
    Filled,
    /// The last filled cell: the color mixed toward white.
    Head,
    /// Filled but de-emphasized: the color at 25% alpha.
    Dimmed,
}

/// Divides `cells` among `parts` of `total` by the largest-remainder method.
///
/// The sum is `round(sum(parts) / total * cells)`, never more than `cells`.
/// A zero `total` gives zeros. A non-zero part that rounds to zero stays zero.
#[must_use]
pub fn allocate_cells(parts: &[u64], total: u64, cells: usize) -> Vec<usize> {
    let mut result: Vec<usize> = vec![0; parts.len()];
    if total == 0 || cells == 0 {
        return result;
    }
    let sum: u128 = parts.iter().map(|&part| u128::from(part)).sum();
    // Parts that exceed the total are scaled down so the chart never overflows.
    let total_wide: u128 = u128::from(total).max(sum);
    let cells_wide: u128 = cells as u128;
    let target: usize =
        (((sum * cells_wide * 2 + total_wide) / (total_wide * 2)).min(cells_wide)) as usize;
    // Exact share of each part, as a numerator over `total`.
    let mut remainders: Vec<(usize, u128)> = Vec::with_capacity(parts.len());
    let mut assigned: usize = 0;
    for (index, &part) in parts.iter().enumerate() {
        let scaled: u128 = u128::from(part) * cells_wide;
        let floor: usize = (scaled / total_wide) as usize;
        if let Some(slot) = result.get_mut(index) {
            *slot = floor;
        }
        assigned += floor;
        remainders.push((index, scaled % total_wide));
    }
    // Largest remainder first; ties go to the earlier part.
    remainders.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    for &(index, remainder) in &remainders {
        if assigned >= target {
            break;
        }
        if remainder == 0 {
            break;
        }
        if let Some(slot) = result.get_mut(index) {
            *slot += 1;
            assigned += 1;
        }
    }
    result
}

/// A cell count as `f32`; counts above 65535 saturate, far beyond any chart.
#[must_use]
pub fn count_f32(count: usize) -> f32 {
    f32::from(u16::try_from(count).unwrap_or(u16::MAX))
}

/// The filled cells for `used` of `total`, rounded half up and clamped.
#[must_use]
pub fn used_cells(used: u64, total: u64, cells: usize) -> usize {
    if total == 0 {
        return 0;
    }
    let total_wide: u128 = u128::from(total);
    let scaled: u128 = u128::from(used) * cells as u128;
    (((scaled * 2 + total_wide) / (total_wide * 2)).min(cells as u128)) as usize
}

/// The index of the first cell of a zone at the end of the chart.
///
/// `threshold_fraction` is the used fraction where the zone begins.
#[must_use]
pub fn zone_start(threshold_fraction: f32, cells: usize) -> usize {
    let fraction: f32 = if threshold_fraction.is_finite() {
        threshold_fraction.clamp(0.0, 1.0)
    } else {
        1.0
    };
    let target: f32 = (fraction * count_f32(cells)).round();
    // The clamped fraction keeps `target` in `0..=cells`, so the search is exact.
    (0..=cells)
        .find(|&index| count_f32(index) >= target)
        .unwrap_or(cells)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parts_sum_to_the_rounded_share() {
        let cells: Vec<usize> = allocate_cells(&[100, 100, 100], 1000, 100);
        assert_eq!(cells.iter().sum::<usize>(), 30);
        let cells: Vec<usize> = allocate_cells(&[1, 1, 1], 3, 10);
        assert_eq!(cells.iter().sum::<usize>(), 10);
    }

    #[test]
    fn small_part_keeps_zero() {
        let cells: Vec<usize> = allocate_cells(&[1, 999], 1000, 10);
        assert_eq!(cells, vec![0, 10]);
    }

    #[test]
    fn zero_total_gives_zeros() {
        assert_eq!(allocate_cells(&[5, 6], 0, 10), vec![0, 0]);
    }

    #[test]
    fn never_more_than_cells() {
        let cells: Vec<usize> = allocate_cells(&[800, 800], 1000, 10);
        assert!(cells.iter().sum::<usize>() <= 10);
    }

    #[test]
    fn used_rounds_half_up_and_clamps() {
        assert_eq!(used_cells(326_500_000_000, 512_000_000_000, 100), 64);
        assert_eq!(used_cells(5, 10, 1), 1);
        assert_eq!(used_cells(0, 10, 100), 0);
        assert_eq!(used_cells(20, 10, 100), 100);
        assert_eq!(used_cells(1, 0, 100), 0);
    }

    #[test]
    fn zone_starts_at_the_threshold() {
        assert_eq!(zone_start(0.9, 100), 90);
        assert_eq!(zone_start(0.75, 20), 15);
        assert_eq!(zone_start(2.0, 20), 20);
        assert_eq!(zone_start(f32::NAN, 20), 20);
    }
}
