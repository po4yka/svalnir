# Svalnir Design

**Status:** Design specification. A first read-only client exists: the window frame, the navigation, the Overview screen, and the Storage screen. "Implementation state" at the end of this document lists what the client does not build yet and where it differs. The client builds on `gpui-kit`; a component in this document is a `gpui-kit` component with these tokens, or a custom element where `gpui-kit` has no equivalent. Each value below is a starting value; record a change here before the code changes.

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

### Theme mapping

The tokens of this document are the source. The application sets them on the `gpui-kit` theme (`ThemeColor` and `Theme`) at startup and when the system appearance changes, so that a `gpui-kit` component shows Svalnir colors with no override at the call site. The names in the right column are fields of the `gpui-kit` theme.

| Svalnir token | `gpui-kit` theme field |
| --- | --- |
| `background` | `background`, `title_bar` |
| `surface` | `sidebar`, `group_box`, `secondary`, `tab_bar` |
| `surface-inset` | `list`, `table`, `input` |
| `surface-raised` | `popover`, `tab_active`, `list_active` |
| `inset-tint` | `muted` |
| `foreground` | `foreground`, `popover_foreground` |
| `muted-foreground` | `muted_foreground` |
| `border` | `border`, `table_row_border`, `sidebar_border` |
| `brand` | `ring`, `selection`, `link`, `info`, `progress_bar` |
| `positive` | `success` |
| `negative` | `danger` |
| `warning` | `warning` |
| Silver primary button | `button_primary` and its hover, active, and foreground fields; the gradient is a Svalnir style on the button |
| Sans, Mono | `font_family`, `mono_font_family` |
| Motion constants of §6 | `motion` (`MotionTokens`) |

`primary` in the `gpui-kit` theme is not `brand`: set `primary` to the silver button color, because `gpui-kit` uses it for the default emphasis of a control. Set `shadow` to off and keep `focus_ring` on. The radii of this document do not fit the two theme radii (`radius`, `radius_lg`); set the radius on each surface. The field names are from `gpui-kit` 0.10.0. `crates/svalnir-gui/src/theme/apply.rs` applies this mapping; §12 lists the differences.

### Categorical palette

Use this order for series and storage categories. Each value has a contrast of 3:1 or more against `surface-inset` and against `surface` in its theme.

| Order | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | Neutral |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Dark | `#0a84ff` | `#5e5ce6` | `#bf5af2` | `#40c8e0` | `#ff375f` | `#ffd60a` | `#30d158` | `#ff9f0a` | `#98989d` |
| Light | `#0071e3` | `#4b49c8` | `#9a3fc9` | `#0a7ea4` | `#d81e5b` | `#8f6a00` | `#248a3d` | `#c93400` | `#6e6e73` |

Colors 1, 7, and 8 are equal to `brand`, `positive`, and `warning` in the two themes. Adjacent colors can be close in hue (1 and 2, 2 and 3), so a chart also separates adjacent segments with a gap and names each category in the legend.

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

The spacing unit is 4 px. Layout gaps and paddings use the steps of this scale.

| Step | Value | Use |
| --- | --- | --- |
| `SPACE_1` | 4 px | A label and its own value or caption |
| `SPACE_2` | 8 px | Rows of one group |
| `SPACE_3` | 12 px | Blocks inside a panel; the same as the gap between shells |
| `SPACE_4` | 16 px | Panel padding; the gap between two columns of one chart block |
| `SPACE_6` | 24 px | A chart and its legend side by side; the content padding of the window |

A layout value outside this scale needs a comment that states the reason.

The radii nest: each inner radius is the outer radius minus the padding between the two.

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

The **shell header** has an icon tile at the left, a title with an optional subtitle, and an aside at the right. The aside holds one item: a status pill, a headline value, or a small action. A card menu (§4) can follow that item as the last element of the header. The **shell footer** holds one suggestion line and at most one action.

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
| Card menu | A `quiet` icon button in the shell header opens an action menu for the card. It holds commands that do not change the system: refresh the data, copy the value, export the data. A view mode stays in a segmented control, and an action that needs approval stays a button |
| Detail card | A non-interactive card on `surface-raised`, anchored to a chart mark. It opens on hover and on keyboard focus of the mark and closes on Escape. It shows a mono title, the time or the scope, and at most six rows in an inset |
| Dialog and sheet | Focus trap; Escape and backdrop close it, except during a confirmation that §7 makes explicit |
| Toast stack | In-window feedback only. A system notification is a separate channel that the agent controls |
| Skeleton, loader, empty state | See §8 for which one a data state uses |
| Key hint | Shows the macOS key symbols |
| Data table | Sortable columns, row selection, mono data cells aligned right |

### Component mapping

Use the `gpui_kit::component` module in the right column for a control. Write a custom element only where the column says so, and build it on `gpui_kit::base` behavior where that exists.

| Control | `gpui-kit` component |
| --- | --- |
| Action button | `button`: `primary`, default (`secondary`), `ghost` (`quiet`), `danger` |
| Segmented control | `tab`, segmented variant |
| Status pill and tag | `tag`, `badge` |
| Progress bar | `progress`. The segmented bar and the stripes are custom |
| Rolling number | Custom element |
| Switch, checkbox, radio group | `switch`, `checkbox`, `radio` |
| Text, search, select, range slider | `input`, `select`, `combobox`, `slider` |
| Tabs, disclosure | `tab`, `collapsible`, `accordion` |
| Tooltip | `tooltip` |
| Action menu, popover | `menu`, `popover` |
| Card menu | `menu` on a `ghost` icon `button` |
| Detail card | `hover_card` |
| Dialog and sheet | `dialog`, `sheet` |
| Toast stack | `notification` |
| Skeleton, loader, empty state | `skeleton`, `spinner`, `empty` |
| Key hint | `kbd` |
| Data table | `table`; `virtual_list` for a long list |
| Shell, panel, inset (§3) | Custom containers; `group_box` is not the three-layer frame |
| Window frame | `title_bar`, `sidebar`, `status_bar` |

The cell and tick components of §5 are custom elements. The rate graph and the step timeline can use `chart` or `plot` where the marks agree with §5. The mapping is not checked against a built view.

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

### LED matrix

The storage charts and the volume strip are LED matrices. This is the signature mark of the client.

- One lattice of small square cells covers the chart: a 4.5 px cell with a 1 px radius and a 1.5 px gap. An empty cell uses `border` at half strength, so the lattice shows in the whole chart.
- A segment is a rectangle of lattice cells with a 1.5 px outline (radius 6 px) in its color, a fill of the color at 8%, and a glow of the color: blur 14 px, alpha 0.45 in the dark theme and 0.22 in the light theme.
- In a segment, each cell is lit (the color mixed 15% toward white) or dim (the color at 28%, or 22% in the light theme). A hash of the cell position and of the segment selects the state, so the pattern has clumps and does not change between frames. About 45% of the cells are lit. The pattern is texture: it has no meaning, and the area of the segment carries the quantity.
- A label in a tile dims the cells under its text only.
- Free space is a region with a dashed 1 px outline (`muted-foreground` at 35%), a label, and sparse bright points. It is not a segment.
- A segment that has no focus while a different one has it shows all its cells dim, its outline at 35%, and no glow.
- The head of a fill is three lattice columns of white at 100%, 60%, and 30% with a white glow.
- Do not draw the glow when Reduce Transparency or Increase Contrast is on, or while the memory pressure state is not normal.

### Dot rings and the session chart

These charts use round dots on the 6 px pitch of the LED matrix. A dot has a diameter of 4 px.

**Headroom dial.** Three concentric rings of dots on a dial face, in a square of 240 px. Each ring is one resource. A ring starts at the top and goes clockwise; the full turn is the capacity of the resource.

- The radii are 90, 76, and 62 px, with 96, 80, and 64 dots. From the outside: the used space of the startup volume, the used swap, and the memory pressure state.
- A dot of the used part is lit: the ring color mixed 15% toward white. A dot of the remaining part is empty: `border` at half strength.
- Space that is available but not free (the system can reclaim it) is the soft part of the disk ring: each second dot in the ring color at 28%. The legend names it.
- The pressure ring has three sectors with a gap of one dot: Normal, Warning, and Critical. The sector of the current state is lit in `positive`, `warning`, or `negative`. The sectors below it are dim, and the sectors above it are empty. The legend states the state as text.
- The last lit dot of a ring is the head: white, with a white glow by the rule of the LED matrix.
- One ring is picked out. The order is: the pressure ring while the state is not normal; the ring with the largest used share above 0; the pressure ring when it is measured; the first measured ring; ring 0. A ring with no capacity or a share of 0 does not win over a measured ring. The picked ring has full strength and a radial marker of 1.5 px by 8 px at its head. The other rings show their lit dots at 55%. Hover or keyboard focus on a legend row picks that ring.
- The center shows the value of the picked ring as a display value and a caption of one line. The center uses the display style: a sans number with a small muted unit, and the caption below. It does not use mono text.
- The dial face is outside the rings. It has 48 tick dots of 2 px at a radius of 102 px in `border`; each twelfth dot is `muted-foreground`. The mono labels "0", "25", "50", and "75" are at a radius of 113 px at the top, right, bottom, and left.
- The start line is a 1 px vertical line in `muted-foreground` from a radius of 52 px to a radius of 98 px at the top, with a dot of 4 px at its outer end.
- Each ring has its name at the left of the start line, at the height of the ring: mono text of 10 px, right-aligned, 6 px from the line. The name of the picked ring has the ring color. The other names use `muted-foreground`.
- The header of the card has one status pill as its aside: the memory pressure state while it is not normal, and otherwise the used share of the startup volume ("49% disk used").
- A detail panel for the picked ring is at the right of the dial, below the legend rows. It is an inset (§3) in the card, not the hover card of §4. It has the name of the ring, its headline value as an aside, and rows of a label and a mono value: for the disk "Used", "Available", "Free", "Reclaimable", and "Total"; for the swap "Used" and "Total"; for the pressure "State" and "Source". One sentence below the rows states what the ring shows. The panel has no control.
- A key is below the dial: one row with the marks "Used", "Reclaimable", and "Empty" and their dots.
- A ring with an unavailable reading shows each second dot empty and no other dot. Its legend row shows an em dash, or the "Unavailable" pill for the pressure ring, and the reason.

**Session chart.** One inset with a value curve and a sample matrix on one time axis. A column of the 6 px pitch is one reading; the newest reading is at the right.

- The curve part has 10 rows. A column shows one dot at the row of the value in the range of the readings on screen, and the dots below it in the series color at 12%. The caption states the range.
- A column with an unavailable reading shows one empty dot on the lowest row.
- The event rail is a 1 px line in `border` above the curve. An event is a marker on the rail: a dot of 6 px for a change of the memory pressure state, and a diamond of 6 px for the admission of the latest operation. The marker has the tone color of the event. A dotted 1 px line goes from the marker down through the chart.
- An event has a label of two mono lines above its marker: the name ("Warning", or the trigger of the operation) in the tone color, and the kind ("pressure" or "operation") in `muted-foreground`. At most four events show a label: the newest four whose labels do not overlap. An older event keeps its marker and its line.
- The newest event has a chip below the rail, at its line: the name, the time of the reading, and one fact ("after 40 normal readings", or the state text of the operation). The chip uses `surface-raised`.
- A dashed 1 px line in `muted-foreground` at 50% marks the lowest value on screen, with a mono label at its right end ("min 260.0 GB").
- The time axis is below the sample matrix: the local time of a reading as mono text ("12:04") at each label step, with a step that keeps 48 px or more between two labels.
- Each row of the sample matrix has its name at the left in mono text ("changes", "disk", "swap", "pressure"), in a gutter that the curve shares. At the right of each row is the newest value of the row in mono text.
- A key is below the chart: the scale "1 column = 1 reading", the marks "Fewer" and "More" with a column of 1 dot and a column of 4 dots, and the mark "Not normal" with a dot in `warning`.
- The footer of the card has mono tags (§4): the number of readings, the range of the available space, the number of events, and the current state.
- The newest column is the live head: a white dot with a glow, and a ring that expands from 4 px to 14 px and fades in 1.6 s. The ring is a continuous effect (§6).
- The sample matrix is below the curve: one row for each series (disk used, swap used, memory pressure). A row is 4 dots high. A column shows 1 to 4 dots: the quarter of the value in the range of that row, or 1, 2, and 4 dots for Normal, Warning, and Critical. A row with one value in its range shows 1 dot in each column.
- A column whose reading has a pressure state that is not normal is picked out: its dots use `warning` or `negative` in each row. The other columns use the row color at 60%.
- The top strip is the change count: 0 to 3 dots for the number of series with a value larger than in the reading before.

**Stat row.** A row of at most four values in the footer of a card or below a chart. A value has a muted label, a 2 px by 8 px dash in the series color, a number in the sans font at 16 px, and a muted suffix at 12 px. The Headroom card shows the available disk space, the used swap, and the pressure state. The folder chart of Storage shows the scanned size, the free space, and the number of causes of unread items.

**Cell ring.** The ring layout of a storage chart: four concentric rings of dots with radii from 66 to 84 px, and 120 angular steps. A segment covers the steps of its share on the four rings, with a gap of one step. Free space shows each second dot empty. The center shows the used value in the display style of the dial center: a sans number, a small muted unit, and the caption below, not mono text. Focus dims the other segments by the rule of the LED matrix.

### Components

| Component | Use in Svalnir |
| --- | --- |
| **Headroom dial** | Disk, swap, and memory pressure as three rings of dots on a dial face with the nearest limit picked out, and a detail panel for the picked ring. The first card of the Overview |
| **Stat row** | Up to four values with a color dash below a chart |
| **Session chart** | The available space of the startup volume since the window opened, with event flags and a live head, over a sample matrix of disk, swap, and pressure |
| **Capacity grid** | Volume capacity as 100 cells at 1% each, filled by category. The warning and critical zones of the disk policy are tinted cells at the end. The inline variant is one row of 20 cells |
| **Cell band** | One horizontal band of cells, split into category segments. The default storage summary |
| **Cell ring, columns, tiles** | Alternative layouts of the same data: share of the volume, comparison between categories, and a treemap. All use one data model and one legend |
| **Tick gauge** | An arc or a line of ticks with a marker at the threshold. Ticks between the value and the threshold use `negative` or `warning`. Use it for memory pressure and headroom |
| **Budget meter** | A row with a name, "value of limit", a bar, and a caption with the time to reset. Use it for application memory budgets, incident budgets, and cooldowns |
| **Tick track** | One row per item with one tick per unit of work. Use it for the steps of an operation and for the candidates of a plan |
| **Rate graph** | A sparkline in an inset with vertical event markers. Use it for the pressure timeline, with one marker per intervention |
| **Step timeline** | Two cumulative step lines around a zero axis, a dotted net line, and activity spans below on the same time axis. Use it for bytes written against bytes reclaimed, and for footprint growth against release |
| **Dot histogram** | One column of dots for each bin of a measured value, symmetric about the axis, with a line at the median and a labeled marker at the limit. Dots past the limit use `negative`. Use it for the footprint samples of one application against its budget, and for the durations of operations |
| **Dot clock** | A ring of 24 hour sectors with one stack of dots for each sector, and the headline value in the center. Use it for interventions by hour of day in the selected range |
| **History track** | One tick for each reading, the newest at the right with a head: `positive`, `warning`, or `negative` for the pressure state, and an empty tick for an unavailable reading. The caption states the number of readings and their source |
| **Value line** | A 1.5 px line of one metric in an inset, with a fill of the line color at 10%, a dot at the newest value, a vertical marker at each change of state, and the range as a caption. An unavailable reading breaks the line |
| **Stat grid** | Overview tiles: a label, a display value, a delta pill, and a thin bar or sparkline |
| **Legend** | A grid of rows: category icon, name, and a mono size aligned right. Each row is a button |

### Rules

- A chart shows one size metric, and its header names that metric: logical size, allocated size, or estimated reclaimable bytes. A treemap is not a statement that each byte can be reclaimed.
- Draw free space as an empty region with a dashed outline and a label. Do not draw it as a category.
- Hover and keyboard focus are linked in both directions. Focus on a legend row dims the other segments, and focus on a segment highlights its row. The status line then shows one sentence about that category.
- A mark that has more detail than its legend row shows a detail card (§4): for example an intervention marker, an activity span, or a tick of an operation. The same text is the accessible description of the mark. A detail card does not hold a control.
- One dot is a stated number of samples or events ("1 dot = 2 samples"), with the same scale in each column or sector of a chart.
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
| **Ring sweep** | When a dial or a cell ring enters, each ring fills clockwise from the top to its measured value in `slow`, with 80 ms between rings. A new reading moves the head to the new value in 250 ms |
| **Live head** | The newest column of the session chart has a ring that expands and fades. A new reading moves each column one step to the left in one frame; the head stays at the right |

### Limits

- A displayed number comes from the agent. A value in motion ends at the measured value and does not go past it. Do not animate toward an estimate as if it were a result.
- Progress shows completed steps. If the total is not known, use an indeterminate state: the head cell and the elapsed time.
- An animation does not suggest that an operation can be reversed. A removal has no reverse animation.
- The idle field and other continuous effects run only in a visible, active window. They stop when the system reports memory pressure, when Low Power Mode is on, and when an incident is open.
- With Reduce Motion on, replace movement with a 150 ms opacity change, apply fills in one step, and turn off the idle field, the particle effect, the peak marker, the ring sweep, and the ring of the live head.
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
- Icons come from Lucide, the icon set that `gpui-kit` bundles. They are outline glyphs at 16 px in rows and 18 px in an icon tile. Take an application icon from the same set; do not mix a second icon set into a view.
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
| Glow on filled cells | A segment of an LED matrix and a head have a soft glow in their color. Accepted on 2026-11-18; this replaces "none in the first release". See "LED matrix" in §5 |
| Component base | `gpui-kit`; see "Theme mapping" in §2 and "Component mapping" in §4 |
| Icon set | Lucide (ISC License), through `gpui_kit::assets` |

The component base and the icon set were accepted after that date, with the change to `gpui-kit`. Include the license text of the bundled fonts and of the icon set with the application.

## 11. Screen map

| Screen | Primary components |
| --- | --- |
| Overview | Headroom dial, session chart, volume strip, guards, last intervention as a phase header |
| Storage | Tiles, cell band, columns, or cell ring; legend, suggestion footer, approval queue |
| Memory | Rate graph with intervention markers, tick gauge, data table of application footprints |
| Applications | Data table, budget meters, protection controls, dot histogram of the footprint samples of the selected application |
| Automation | Policy forms, range sliders for thresholds, budget meters, pause control |
| History | Data table, tick track per operation, step timeline, dot clock of interventions by hour |
| Diagnostics | Status pills for each permission and service, empty states with the fix |
| Menu bar | Inline capacity grid, pressure pill, pause control |

## 12. Implementation state

The first client in `crates/svalnir-gui` applies sections 2 to 6 and section 8 to two screens. No recorded evidence under [VALIDATION.md](docs/VALIDATION.md) covers it. These points differ from this document or are not built.

| Subject | State |
| --- | --- |
| Theme mapping (§2) | Applied at the start and when the system appearance changes. The theme holds solid colors; the action button of the client draws the silver gradient itself |
| Fonts (§2) | Geist and Geist Mono are in the binary. Tabular figures and the tracking of the screen title are not applied; the rolling number gives each digit the same width |
| Icons (§9) | The default icon bundle of `gpui-kit` has no clock or history glyph. History uses a document glyph and Diagnostics uses an inspector glyph |
| Controls (§4) | The segmented control and the action button are custom. The segmented control estimates the width of an option from its text length |
| LED matrix (§5) | Built for tiles, band, columns, and the volume strip. The glow turns off for Reduce Transparency, Increase Contrast, and a memory pressure state that is not normal; the client reads the two display settings when its window becomes active. The width of a tile label is an estimate |
| Storage breakdown (§5, §10) | The resource model defines no storage categories, and the scanner reports none. The Storage screen shows the direct children of the scan root in palette order by size. At the default scan root the chart has the scale of the volume, with the free space and a "Not scanned" segment |
| Linked focus (§5) | Hover on a legend row dims the other segments, in the tiles, band, columns, and ring layouts, and picks a ring of the headroom dial. Keyboard focus on a dial row picks its ring and blur clears the pick, like hover; a click on a dial row picks its ring. The cell ring selects and hovers a segment by its whole arc |
| Charts (§5) | Built: LED tiles, band, and columns; the headroom dial; the session chart; the cell ring; the history track label of the pressure row; the legend. The tick gauge, the value line, and the sparkline were removed from the Overview. Differences: the radial marker of the dial is painted as eight small squares along the radius; the dots of the cell ring are 3 px, because the inner ring has 3. The times of the session chart are local time; a reading with no known zone offset shows UTC, and the chart then says "UTC". Not built: budget meter, tick track of an operation, rate graph with interventions, step timeline, stat grid (the stat row is built), dot histogram, dot clock |
| Motion (§6) | Built: scan fill with a head, rolling number, fill-in of a finished chart, idle field in the free region, card entry, sliding pill, the ring sweep of the dial (with each entry of the Overview cards) and of the cell ring, the move of a dial ring head to a new reading in 250 ms (`FRONT_EASE`, `ease-ui-out`, a lit count that ends at the measured count; it runs per frame and only without Reduce Motion), the ring of the live head (1.6 s period from its own start instant, per frame, and it stops with the other continuous effects). Not built: removal, phase header, outcome line, range change, expand, peak marker |
| History (§5) | The history track and the value line show the readings of this window since it opened, at most 180. The client reads no stored samples |
| Screens (§11) | Overview and Storage are built without a state-changing action. The other five screens show a placeholder. No menu bar item exists |
| Accessibility (§9) | Each chart has a text label and each state has text. Increase Contrast, Reduce Transparency, and a screen reader are not checked |
