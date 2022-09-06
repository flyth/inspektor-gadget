# TextColumns Formatter

This formatter can output structs (and events of structs) using metadata from a `Columns` helper in a tabular way
suitable for consoles or other frontends using fixed-width characters / fonts.

It can automatically size the output tables according to either screen size or content and provides some helpful tools
to get a consistent output.

## Initializing

You can create a new formatter by calling

```
tc := textcolumns.NewFormatter(columnMap)
```

You can specify options by adding one or more of the WithX() functions to the initializer.
The `ColumnMap` can be obtained by calling `GetColumpMap()` on your `Column` instance. 

## Output

After you have initialized the formatter, you can use `tc.FormatHeader()` to obtain the header line as string, which
will look something like this:

```
NODE                PID COMM             NAME                                 TIME
```

You can also pass a filled struct to `tc.FormatEntry(&event)` to get a string like this:

```
Node1                 2 AAA                                                   12ns
```

Even simpler, use `tc.WriteTable(os.Stdout, entries)` to directly print the whole table:

```
NODE                PID COMM             NAME                                 TIME
----------------------------------------------------------------------------------
Node1                 2 AAA                                                   12ns
Node1                 1 AAA              Yay                           14.677772ms
Node1                 2 AnotherComm                                    24.645772ms
Node2                 4 BBB                                           3.462217772s
Node2                 3 BBB                                                  333ns
```


### Options

| Field             | Value  | Description                                                                       |
|-------------------|--------|-----------------------------------------------------------------------------------|
| AutoScale         | bool   | if enabled, the screen size will be used to scale the widths                      |
| ColumnDivider     | string | defines the string that should be used as spacer in between columns (default " ") |
| HeaderStyle       | type   | defines how column headers are decorated (e.g. uppercase/lowercase)               |
| RowDivider        | string | defines the (to be repeated) string that should be used below the header          |
| ShowRowDivider    | bool   | enables/disables the use of the row divider (below header)                        |


#### Custom Columns

By default, Columns will show all fields that have a column tag without the `hide` attribute. Using
`tc.SetShowColumns("node,time")` you can adjust the output to contain exactly the specified columns.
