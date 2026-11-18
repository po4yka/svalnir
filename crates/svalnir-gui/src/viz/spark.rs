//! The swap sparkline of the Overview.

use crate::{
    data::model::{HostSample, Measured},
    theme::tokens::{Tokens, to_hsla},
};
use gpui_kit::{
    App, Bounds, Hsla, IntoElement, ParentElement as _, Pixels, RenderOnce, Styled as _, Window,
    canvas, component::ActiveTheme as _, div, fill, point, px, size,
};

/// Height of the sparkline inset.
pub const SPARK_HEIGHT: f32 = 56.0;

/// A point of the line in pixels inside the inset, or `None` for a break.
pub type SparkPoint = Option<(f32, f32)>;

/// Maps `values` to points in a `width` by `height` box; the y scale is
/// `0..=max`. An unavailable value maps to `None`: no interpolation.
#[must_use]
pub fn spark_points(values: &[Option<u64>], max: u64, width: f32, height: f32) -> Vec<SparkPoint> {
    let n: usize = values.len();
    #[expect(clippy::cast_precision_loss, reason = "pixel mapping of small counts")]
    let step: f32 = if n > 1 { width / (n - 1) as f32 } else { 0.0 };
    #[expect(clippy::cast_precision_loss, reason = "pixel mapping")]
    let scale: f32 = if max == 0 { 0.0 } else { height / max as f32 };
    values
        .iter()
        .enumerate()
        .map(|(i, v)| {
            v.map(|v| {
                #[expect(clippy::cast_precision_loss, reason = "pixel mapping")]
                let x: f32 = i as f32 * step;
                #[expect(clippy::cast_precision_loss, reason = "pixel mapping")]
                let y: f32 = (height - v.min(max) as f32 * scale).clamp(0.0, height);
                (x, y)
            })
        })
        .collect()
}

/// The runs of consecutive points; a `None` ends a run.
#[must_use]
pub fn runs(points: &[SparkPoint]) -> Vec<Vec<(f32, f32)>> {
    let mut out: Vec<Vec<(f32, f32)>> = Vec::new();
    let mut current: Vec<(f32, f32)> = Vec::new();
    for p in points {
        match p {
            Some(p) => current.push(*p),
            None => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// The sample indices where the pressure level differs from the sample before.
#[must_use]
pub fn level_changes(history: &[HostSample]) -> Vec<usize> {
    let mut out: Vec<usize> = Vec::new();
    for i in 1..history.len() {
        if let (Measured::Value(a), Measured::Value(b)) =
            (&history[i - 1].pressure, &history[i].pressure)
            && a != b
        {
            out.push(i);
        }
    }
    out
}

/// The sparkline: the line, the area, the newest dot, and the level markers.
#[derive(IntoElement, Debug)]
pub struct Sparkline {
    values: Vec<Option<u64>>,
    max: u64,
    changes: Vec<usize>,
    color: Hsla,
}

impl Sparkline {
    /// Creates the sparkline of `values` (oldest first) on the scale `0..=max`.
    pub fn new(values: Vec<Option<u64>>, max: u64, changes: Vec<usize>, color: Hsla) -> Self {
        Self {
            values,
            max,
            changes,
            color,
        }
    }
}

impl RenderOnce for Sparkline {
    fn render(self, _window: &mut Window, cx: &mut App) -> impl IntoElement {
        let tokens: &Tokens = Tokens::for_dark(cx.theme().is_dark());
        let muted: Hsla = to_hsla(tokens.muted_foreground).opacity(0.6);
        let Self {
            values,
            max,
            changes,
            color,
        } = self;
        div()
            .h(px(SPARK_HEIGHT))
            .w_full()
            .rounded(px(12.0))
            .bg(to_hsla(tokens.inset_tint))
            .child(
                canvas(
                    |_, _, _| (),
                    move |bounds: Bounds<Pixels>, (), window: &mut Window, _: &mut App| {
                        let pad: f32 = 6.0;
                        let w: f32 = (f32::from(bounds.size.width) - 2.0 * pad).max(1.0);
                        let h: f32 = (f32::from(bounds.size.height) - 2.0 * pad).max(1.0);
                        let at = |x: f32, y: f32| {
                            point(bounds.origin.x + px(pad + x), bounds.origin.y + px(pad + y))
                        };
                        let points = spark_points(&values, max, w, h);
                        for i in &changes {
                            if let Some(Some((x, _))) = points.get(*i) {
                                window.paint_quad(fill(
                                    Bounds::new(at(*x, 0.0), size(px(1.0), px(h))),
                                    muted,
                                ));
                            }
                        }
                        for run in runs(&points) {
                            if run.len() >= 2 {
                                let mut area = gpui_kit::PathBuilder::fill();
                                area.move_to(at(run[0].0, h));
                                for (x, y) in &run {
                                    area.line_to(at(*x, *y));
                                }
                                area.line_to(at(run[run.len() - 1].0, h));
                                area.close();
                                if let Ok(path) = area.build() {
                                    window.paint_path(path, color.opacity(0.1));
                                }
                                let mut line = gpui_kit::PathBuilder::stroke(px(1.5));
                                line.move_to(at(run[0].0, run[0].1));
                                for (x, y) in run.iter().skip(1) {
                                    line.line_to(at(*x, *y));
                                }
                                if let Ok(path) = line.build() {
                                    window.paint_path(path, color);
                                }
                            }
                        }
                        if let Some(Some((x, y))) = points.last() {
                            window.paint_quad(
                                fill(
                                    Bounds::new(at(*x - 3.0, *y - 3.0), size(px(6.0), px(6.0))),
                                    color,
                                )
                                .corner_radii(px(3.0)),
                            );
                        }
                    },
                )
                .size_full(),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn y_maps_zero_to_the_bottom_and_max_to_the_top() {
        let p = spark_points(&[Some(0), Some(50), Some(100)], 100, 100.0, 40.0);
        assert_eq!(p[0], Some((0.0, 40.0)));
        assert_eq!(p[1], Some((50.0, 20.0)));
        assert_eq!(p[2], Some((100.0, 0.0)));
    }

    #[test]
    fn an_unavailable_sample_breaks_the_line() {
        let p = spark_points(&[Some(1), None, Some(2), Some(3)], 3, 30.0, 10.0);
        assert_eq!(p[1], None);
        let r = runs(&p);
        assert_eq!(r.len(), 2);
        assert_eq!((r[0].len(), r[1].len()), (1, 2));
    }
}
