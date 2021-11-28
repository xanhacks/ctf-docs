---
title: Tmux cheatsheet
description: Tmux shortcut combinaison and description.
---

# Tmux cheatsheet

**tmux** is a terminal multiplexer : it enables a number of terminals to be created, accessed, and controlled from a single screen. tmux may be detached from a screen and continue running in the background, then later reattached

## Shortcuts

- `CTRL + B` + `c` : Create a new window.
- `CTRL + B` + `,` : Rename a window.
- `CTRL + B` + `"` : Create a new pane (horizontally and below the current pane).
- `CTRL + B` + `%` : Create a new pane (vertically and to the right of the current pane).
- `CTRL + B` + `!` : Transform a pane to a new window.
- `CTRL + B` + `z` : Enable / Disable the zoom mode on a pane.
- `CTRL + B` + `x` : Kill the current pane.
- `CTRL + B` + `arrow` : Resize the current pane.
- `CTRL + B` + `[0-9]` : Switch to the window n°[0-9].
- `CTRL + B` + `{` : Move the current pane to the left.
- `CTRL + B` + `}` : Move the current pane to the right.
- `CTRL + B` + `[` : Enter in *copy* mode.
- `CTRL` + `S` : Search text (only on *copy* mode).
- `CTRL+B` + `s` : Select a running session.

## Configuration

The **tmux** configuration file is located at `~/.tmux.conf`.

### Default shell

```
set -g default-shell /usr/bin/fish
```

### New window / pane come with the current path

```
bind c new-window -c "#{pane_current_path}"
bind '"' split-window -c "#{pane_current_path}"
bind % split-window -h -c "#{pane_current_path}"
```