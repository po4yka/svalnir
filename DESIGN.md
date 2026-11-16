# Svalnir Design

**Status:** Design specification. No GPUI view exists. The client builds on `gpui-kit`; a component in this document is a `gpui-kit` component with these tokens, or a custom element where `gpui-kit` has no equivalent. Each value below is a starting value; record a change here before the code changes.

This document owns the visual language of the GPUI client: tokens, surfaces, components, data visualization, and motion. The screen list is in the [README](README.md#gpui-desktop-experience). The presentation requirements that bind each screen are in [INTERFACES.md §14](docs/INTERFACES.md#14-gpui-parity-and-presentation). Metric meaning is in [RESOURCE_MODEL.md](docs/RESOURCE_MODEL.md), and operation states are in [ACTION_CONTRACTS.md](docs/ACTION_CONTRACTS.md). Where this document disagrees with one of those, that document takes precedence.

## 1. Character

The interface reads as an instrument, not as a marketing page. These rules decide a design question that the later sections do not cover.

1. **Depth comes from tone.** A surface is one step lighter or darker than its parent. Surfaces have no border and no drop shadow.
2. **Quantity is discrete.** Cells and ticks show amounts. One cell is a stated amount, so a reader can count.
3. **Numbers are the headline.** Each card leads with one large value and its unit. Supporting text is small and muted.
4. **Color has a job.** Neutral grays carry the layout. A hue marks a state, a series, or a category, and a text label always accompanies it.
5. **Motion reports a state change.** An animation starts when data changes and ends at the measured value. Decorative loops are limited to the idle field in §6.
6. **Dark first.** The dark theme is the reference. The light theme uses the same tokens with the values in §2.

## 2. Tokens

### Color

| Token | Dark | Light | Use |
| --- | --- | --- | --- |
| `background` | `#0c0c0c` | `#f7f7f8` | Window |
| `surface` | `#191919` | `#ededef` | Shell |
| `surface-inset` | `#101010` | `#ffffff` | Panel |
| `surface-raised` | `#252525` | `#e2e2e4` | Popover, menu, tooltip, active segment |
| `inset-tint` | foreground at 4% | foreground at 4% | Inset block inside a panel |
| `foreground` | `#f5f5f5` | `#161618` | Primary text and values |
| `muted-foreground` | `#98989b` | `#636368` | Labels, units, secondary text |
| `border` | white at 6% | `#161618` at 7% | Dividers and empty cells only |
| `brand` | `#0a84ff` | `#0071e3` | Activity in progress, selection, focus ring |
| `positive` | `#30d158` | `#248a3d` | Verified good outcome |
| `negative` | `#ff453a` | `#d70015` | Failure, destructive action |
| `warning` | `#ff9f0a` | `#c93400` | Threshold near, partial or unknown outcome |

A tinted fill for a pill or a danger button is the tone at 15% over its surface, with the tone as the text color.

The primary button is silver, not `brand`: a vertical gradient from `#ababab` to `#ffffff` in the dark theme and from `#e6e6e6` to `#ffffff` in the light theme, with `#111111` text. The secondary button is a gradient from `#1d1d1d` to `#262626` in the dark theme and from `#e2e2e2` to `#ececec` in the light theme.

### Categorical palette

Use this order for series and storage categories. The dark values are given; select light values that have a contrast of 3:1 or more against `surface-inset`.

| Order | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | Neutral |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Dark | `#0a84ff` | `#5e5ce6` | `#bf5af2` | `#40c8e0` | `#ff375f` | `#ffd60a` | `#30d158` | `#ff9f0a` | `#98989d` |

Use the neutral color for system-managed and unclassified data. Do not use `negative` as a category color. Inside a category chart, a hue identifies a category only; show a state with a pill, an icon, or text.

### Typography

| Role | Font | Size / weight | Use |
| --- | --- | --- | --- |
| Display value | Sans | 30 px / 500, tabular figures | Headline number of a card |
| Screen title | Sans | 24 px / 600, tracking −0.025 em | One per screen |
| Card title | Sans | 15 px / 500 | Shell header |
| Body | Sans | 14 px / 400 | Rows, descriptions |
| Caption | Sans | 12 px / 400, muted | Subtitle, axis, footer |
| Data | Mono | 12 px or 13 px / 400 | Sizes, durations, paths, PIDs, IDs, rule IDs |
| Overline | Mono | 11 px / 500, uppercase, tracking 0.025 em | Section label, provenance line |

Sans is Geist and Mono is Geist Mono (SIL Open Font License 1.1). Svalnir bundles both and falls back to the system fonts.

All changing numbers use tabular figures. A value and its unit stay together: the value in `foreground`, the unit and the context ("of 512 GB used") in `muted-foreground` at caption size.

### Shape and spacing

The spacing unit is 4 px. The radii nest: each inner radius is the outer radius minus the padding between the two.

| Element | Radius | Size |
| --- | --- | --- |
| Shell | 22 px | Padding 6 px |
| Panel | 16 px | Padding 16 px; 12 px in dense lists |
| Inset | 12 px | Padding 12 px × 14 px |
| Icon tile | 10 px | 36 px square |
| Button, segmented control | Full pill | 32 px (`sm`), 36 px (`md`) |
| Status pill | Full pill | 20 px (`sm`), 24 px (`md`) |
| Bar | Full pill | 6, 8, or 12 px high |
| Cell | 3 px | 14 px with a 4 px gap in a grid; scale down for dense charts |

A card is 448 px wide by default. A dashboard is a grid of shells with a 12 px gap.

## 3. Surfaces

Each component is framed by the same three layers.

| Layer | Fill | Content |
| --- | --- | --- |
| **Shell** | `surface` | Header and footer sit directly in the shell padding |
| **Panel** | `surface-inset` | Main content |
| **Inset** | `inset-tint` | Code, paths, payloads, detail one level deeper |

The **shell header** has an icon tile at the left, a title with an optional subtitle, and an aside at the right. The aside holds one item: a status pill, a headline value, or a small action. The **shell footer** holds one suggestion line and at most one action.

Popovers, menus, tooltips, and dialogs use `surface-raised`. They are the only elements that can have a shadow.

## 4. Controls

Each control has full keyboard behavior.

| Control | Rules for Svalnir |
| --- | --- |
| Action button | `primary` (silver), `secondary`, `quiet`, `danger`. One `primary` per view. `loading` replaces the icon with a spinner and disables the button |
| Segmented control | Active pill slides for a pointer and jumps for the keyboard. Use it for time range, view mode, and scope |
| Status pill and tag | Five tones. A pill always contains text. A mono tag shows a rule ID, a volume, or a bundle ID |
| Progress bar and segmented bar | `progress` for work toward an end, `meter` for a level. Stripes mark an estimate or a period in progress |
| Rolling number | Each digit rolls to its new value; units and separators stay in position |
| Switch, checkbox, radio group | A checkbox has a mixed state for partial selection of a group |
| Text, search, select, range slider | The range slider sets thresholds; show the value and its unit next to the handle |
| Tabs, disclosure | Sliding indicator; smooth height change |
| Tooltip | 300 ms delay on the first hover, then immediate while one is warm |
| Action menu, popover | A destructive group is separated and uses `negative` |
| Dialog and sheet | Focus trap; Escape and backdrop close it, except during a confirmation that §7 makes explicit |
| Toast stack | In-window feedback only. A system notification is a separate channel that the agent controls |
| Skeleton, loader, empty state | See §8 for which one a data state uses |
| Key hint | Shows the macOS key symbols |
| Data table | Sortable columns, row selection, mono data cells aligned right |

Action classes map to button variants as follows.

| Action class | Variant | Label pattern |
| --- | --- | --- |
| `MoveToTrash` | `primary` or `secondary` | "Move to Trash" |
| `EvictRegenerableData` | `primary` or `secondary` | "Clear" plus the rule name |
| `DeleteSelectedFiles` | `danger` | "Delete permanently" |
| `RequestApplicationExit` | `secondary` | "Quit" plus the application name |
| `ForceApplicationExit` | `danger` | "Force quit" plus the application name |

A label names the action and its object. Do not use "OK", "Clean", or "Optimize".

## 5. Data visualization

### Cells and ticks

A **cell** is a small rounded square. A **tick** is a thin vertical bar. Both are the default marks for a quantity, and both use the same four states.

| State | Appearance |
| --- | --- |
| Empty | `border` color |
| Filled | Series or category color |
| Head | The filled color mixed toward white; marks the position of work in progress |
| Dimmed | The filled color at 25%; a different item has the focus |

State the scale near the chart or in its accessible label ("1 cell = 1%"). A chart that has more cells than data resolution misleads; reduce the cell count.

### Components

| Component | Use in Svalnir |
| --- | --- |
| **Capacity grid** | Volume capacity as 100 cells at 1% each, filled by category. The warning and critical zones of the disk policy are tinted cells at the end. The inline variant is one row of 20 cells |
| **Cell band** | One horizontal band of cells, split into category segments. The default storage summary |
| **Cell ring, columns, tiles** | Alternative layouts of the same data: share of the volume, comparison between categories, and a treemap. All use one data model and one legend |
| **Tick gauge** | An arc or a line of ticks with a marker at the threshold. Ticks between the value and the threshold use `negative` or `warning`. Use it for memory pressure and headroom |
| **Budget meter** | A row with a name, "value of limit", a bar, and a caption with the time to reset. Use it for application memory budgets, incident budgets, and cooldowns |
| **Tick track** | One row per item with one tick per unit of work. Use it for the steps of an operation and for the candidates of a plan |
| **Rate graph** | A sparkline in an inset with vertical event markers. Use it for the pressure timeline, with one marker per intervention |
| **Step timeline** | Two cumulative step lines around a zero axis, a dotted net line, and activity spans below on the same time axis. Use it for bytes written against bytes reclaimed, and for footprint growth against release |
| **Stat grid** | Overview tiles: a label, a display value, a delta pill, and a thin bar or sparkline |
| **Legend** | A grid of rows: category icon, name, and a mono size aligned right. Each row is a button |

### Rules

- A chart shows one size metric, and its header names that metric: logical size, allocated size, or estimated reclaimable bytes. A treemap is not a statement that each byte can be reclaimed.
- Draw free space as an empty region with a dashed outline and a label. Do not draw it as a category.
- Hover and keyboard focus are linked in both directions. Focus on a legend row dims the other segments, and focus on a segment highlights its row. The status line then shows one sentence about that category.
- A threshold is a marker with a label on the chart. Do not show a threshold by color only.
- A failed or stale value is not zero. See §8.
- The color scale of a tick gauge follows the meaning of the metric. For a usage metric, the high end is `negative`.

## 6. Motion

### Constants

| Token | Value | Use |
| --- | --- | --- |
| `ease-ui-out` | `cubic-bezier(0.23, 1, 0.32, 1)` | Default for entry and for value changes |
| `ease-drawer` | `cubic-bezier(0.32, 0.72, 0, 1)` | Sheets and large panels |
| `ease-standard` | `cubic-bezier(0.4, 0, 0.2, 1)` | Color and opacity changes |
| `fast` | 150 ms | Hover, press, color |
| `base` | 200 to 250 ms | Segmented pill, tabs, tooltip, menu |
| `enter` | 320 ms | Card or row entry: fade and move up 6 px |
| `slow` | 500 to 700 ms | Bar fill, gauge sweep, chart redraw |
| `digit-stagger` | 24 ms | Delay between adjacent digits, right to left |
| `cell-stagger` | 8 to 12 ms | Delay between adjacent cells or ticks |

An element exits faster than it enters. An action from the keyboard skips the slide and applies the end state.

### Patterns

| Pattern | Behavior |
| --- | --- |
| **Scan fill** | Cells fill in the order of the scan, with a head cell at the front. The headline value rolls up with the measured total. The status line shows the phase and the current path in mono. When the scan ends, the head goes out and the footer changes from the phase text to a suggestion |
| **Phase header** | The header title, the icon tile, and the counters change in position when the phase changes: for example "Scanning", "Clearing caches", "Verifying", and then the outcome. The elapsed time is mono text in the aside |
| **Removal** | Cells of the affected segment go out from the end of the segment. The segment, the headline value, and the legend value decrease together, and each stops at the measured value. A short particle effect at the edge is optional |
| **Outcome line** | A check icon and one sentence with the observed result replace the phase text. The next suggestion follows, or the text that there is none |
| **Range change** | When the time range changes, the ticks refill from left to right with `cell-stagger`, and the value rolls |
| **Expand** | A card grows in position to show a breakdown. The other cards move; they do not jump |
| **Peak marker** | A thin line stays at the maximum of a column and then falls to the current value |
| **Idle field** | Sparse points fade in and out in the empty area of a cell chart |

### Limits

- A displayed number comes from the agent. A value in motion ends at the measured value and does not go past it. Do not animate toward an estimate as if it were a result.
- Progress shows completed steps. If the total is not known, use an indeterminate state: the head cell and the elapsed time.
- An animation does not suggest that an operation can be reversed. A removal has no reverse animation.
- The idle field and other continuous effects run only in a visible, active window. They stop when the system reports memory pressure, when Low Power Mode is on, and when an incident is open.
- With Reduce Motion on, replace movement with a 150 ms opacity change, apply fills in one step, and turn off the idle field, the particle effect, and the peak marker.
- Limit continuous rendering to the cards on screen. Paint cells as plain quads in one custom element; a chart does not need one view per cell.
- The interface has no sound.

## 7. Honest states

These rules apply the contracts in [INTERFACES.md §14](docs/INTERFACES.md#14-gpui-parity-and-presentation) and [ACTION_CONTRACTS.md](docs/ACTION_CONTRACTS.md) to the visuals.

### Operation states

| State | Tone | Icon | Motion |
| --- | --- | --- | --- |
| `Prepared`, `Admitted` | Neutral | Clock | None |
| `IntentCommitted`, `DispatchConsumed` | `brand` | Spinner | Head tick on the current step |
| `Verifying` | `brand` | Spinner | Head tick; no outcome text yet |
| `Completed` | `positive` | Check | Outcome line |
| `Partial`, `Incomplete` | `warning` | Half circle | Outcome line with done and not-done counts |
| `NoAction` | Neutral | Minus | None |
| `Failed` | `negative` | Cross | None |
| `UnknownOutcome` | `warning` | Question mark | None; show what is known and the recovery step |

`UnknownOutcome` and `Failed` are different states and have different icons, tones, and text.

### Wording and placement

- "Freed" or "Reclaimed" is followed by an observed capacity change. A move to the Trash shows "Moved to Trash" and the transferred size; the capacity value does not change.
- An estimate has the prefix "about" or the label "Estimated", and its bar has stripes. The stripes go away when a measured value replaces the estimate.
- An application shows "Quit" or "Force quit" as done only after the agent confirms the exit. Until then, the row shows "Waiting for exit" and the elapsed time.
- Force escalation is a visible step in the tick track, with its own label.
- An approval view shows the scope, the action classes, the item count, the size metric, and the expiry of the plan. When the plan is not current, the view changes to an expired state and removes the action button.
- A confirmation for a `danger` action is a dialog that names the object and the consequence. The `danger` button is not the default button. Escape cancels.
- A dispatched action has no "Undo" control. Offer cancellation only where the action contract permits it, and name it "Cancel".
- Pausing automation, canceling one operation, and closing the window are three controls with three labels in three places: the automation header, the operation row, and the window.

### Approval queue

Plans that wait for approval show in a queue: groups by risk with the highest first, expandable rows with the detail in an inset, a selection checkbox for each row, and a decision row with one `secondary` and one `primary` or `danger` button. The grant scopes come from [POLICY_SPEC.md](docs/POLICY_SPEC.md).

## 8. Data states

| Data state | Presentation |
| --- | --- |
| Loading, first time | Skeleton in the shape of the content |
| Refreshing | Keep the last value; show a small spinner in the header aside |
| Stale | Keep the value in `muted-foreground`; show the age in a caption ("12 min ago") |
| Unavailable | An em dash in place of the value and a one-line reason. Empty cells; no zero |
| Partial | The value with a "partial" tag; the missing part as a hatched region |
| Permission denied | Empty state with the name of the permission and a link to Diagnostics |
| Empty | Empty state with one sentence and at most one action |
| Agent disconnected | A banner at the top of the window; all values change to stale |

A provenance line in overline style can close a card: the source, the sample time, and the scope of the measurement.

## 9. Accessibility and platform

- Each interactive element has a label, a visible focus ring in `brand` (2 px, with a 2 px offset), and a keyboard path. A chart is one focus stop; the arrow keys move between its segments.
- A chart has a text alternative: the headline value, and the legend as a list.
- State uses a minimum of two signals: tone with an icon, or tone with text.
- Body text has a contrast of 4.5:1 or more. Marks and large values have 3:1 or more. Check both themes.
- Honor the macOS settings Reduce Motion, Increase Contrast, and Reduce Transparency. With Increase Contrast on, surfaces get a 1 px `border` outline.
- Icons are filled glyphs at 16 px in rows and 18 px in an icon tile. Line glyphs such as the check, the cross, and arrows use a bold weight.
- The window is resizable. The grid changes from three columns to two and then to one. A card does not go below 320 px.
- The menu bar item shows the inline capacity grid, the memory pressure state as a pill, and the pause control. It has no animation other than a state change.

## 10. Decisions

These decisions were accepted on 2026-11-16.

| Subject | Decision |
| --- | --- |
| Fonts | Bundle Geist and Geist Mono; fall back to the system fonts |
| Light theme | The first release includes it and follows the system appearance |
| Storage categories and their colors | Take the categories from the resource model; assign palette colors in a fixed order |
| Default storage layout | Cell band in Overview; tiles in Storage |
| Glow on filled cells | None in the first release |

The icon set is not selected. Include the license text of the bundled fonts with the application.

## 11. Screen map

| Screen | Primary components |
| --- | --- |
| Overview | Stat grid, inline capacity grid, tick gauge for memory pressure, last intervention as a phase header |
| Storage | Cell band or tiles, legend, suggestion footer, approval queue |
| Memory | Rate graph with intervention markers, tick gauge, data table of application footprints |
| Applications | Data table, budget meters, protection controls |
| Automation | Policy forms, range sliders for thresholds, budget meters, pause control |
| History | Data table, tick track per operation, step timeline |
| Diagnostics | Status pills for each permission and service, empty states with the fix |
| Menu bar | Inline capacity grid, pressure pill, pause control |
