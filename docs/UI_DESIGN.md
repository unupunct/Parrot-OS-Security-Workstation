# MATRIX PRO interface

Colours, spacing and type live in one place: `src/wifi_center/ui/design/tokens.py`. The stylesheet
(`ui/theme.py`) and every component read from it; a test fails if the retired palette reappears in the UI code.

## Building blocks (`ui/design/`)

| Module | Contents |
|---|---|
| `tokens.py` | Palette, spacing, type, `with_alpha`, `mix` |
| `icons.py` | One vector line-icon set drawn with QPainter, recoloured on demand (cached) |
| `components.py` | `MatrixButton`, `Panel` (MatrixCard), `MetricTile`, `StatusDot`, `StatusChip`, `Badge`, `LogoWidget`, `GaugeWidget`, `LoadingIndicator` (radar / ring / scan / nodes) |
| `motion.py` | Shared frame clock, intensity (low / normal / high), reduced motion, `fade_in`, `animate_value`, per-effect frame-rate caps |
| `matrix_rain.py` | Matrix rain (persistent-pixmap fade technique) |
| `graph_layout.py` | Radial seed + force-directed layout (NumPy, no Qt) |
| `overlay.py` | Startup transition |

Higher level: `sidebar.py`, `topbar.py`, `palette.py` (Ctrl+K), `notifications.py`, `board.py` (rearrangeable
responsive widget board), `topology.py` (network map), `radar.py` (wireless radar), `dashboard.py`.

## Animation and performance

* One `QTimer` clock for all continuous effects. It runs only when an animated widget is visible, the application is
  active and reduced motion is off; widgets subscribe on show and unsubscribe on hide.
* Heavy effects are frame-rate capped by intensity (topology and radar 20 / 12 / 6 fps, rain 12 / 8 / 4 fps).
* Matrix rain is deliberately **not** full screen: every rain frame repaints the widgets that overlap it, so on the
  dashboard it is a fading band behind the page header. It is full screen only during the short startup transition.
* Settings → Appearance: intensity (default High), reduced motion, startup transition. Headless platforms never animate.
* Measured on the development machine (Windows, 125 % scaling, software rendering), dashboard at 1600×900:
  High 29 % of one core, Low 19 %, Reduced motion 5–8 %, dashboard hidden about 0 %.

## What is real data

The topology shows this computer, the default gateway (from the routing table) and neighbours from the kernel
ARP/neighbour cache, plus hosts stored in the database (for example imported Nmap results). Nothing is probed and nothing
is invented; with no neighbours the view shows an empty state. The wireless radar plots stored scan observations: distance
is signal strength and angle is the channel's position in its band (a Wi-Fi scan has no direction, and the widget says so).

## Rearranging the dashboard

"Rearrange" shows move and width buttons on the lower panels. Order and width are saved in the settings database and
restored on start. Column count follows the window width (4 / 3 / 2 / 1).
