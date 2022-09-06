# Ellipsis helper

Sometimes a string just won't fit into a given width. This library will shorten the output so that it fits
nicely. It can either just cut the text after the given width or replace the missing part with an ellipsis ("…"). In
some cases it's really helpful to have this in the middle of a string, so this is also implemented.

## Example Output

| Text         | Width        | Ellipsis Style | Output |
|--------------|--------------|----------------|--------|
| Foobar123    | 4            | None           | Foob   |
| Foobar123    | 4            | End            | Foo…   |
| Foobar123    | 4            | Start          | …123   |
| Foobar123    | 4            | Middle         | Fo…r   |
