# ui/grid.py
def grid_evenly(container, widgets, num_cols=2, padx=12, pady=12):
    # Configure columns to have equal width
    for c in range(num_cols):
        container.grid_columnconfigure(c, weight=1, uniform="col")

    # Clear old grid (keep widgets existing; we’ll re-grid)
    for w in widgets:
        w.grid_forget()

    # Place in rows/cols
    for i, w in enumerate(widgets):
        r, c = divmod(i, num_cols)
        w.grid(row=r, column=c, sticky="nsew", padx=padx, pady=pady)
