# Filtering

If you have an array of a struct you have a `Column` instance for, you can simply filter it by using a filter string
like this:

```
filter.FilterEntries(columnMap, events, []string{"pid:55"})
```

This will return an array only containing entries that have the pid column set to 55.

A filter string always starts with the column name, followed by a colon and then the actual filter rule.

If the filter rule starts with an exclamation mark ("!"), the filter will be negated and return only entries that don't
match the rule. This indicator has always be the first character of the filter rule.

```
filter.FilterEntries(columnMap, events, "name:!Demo") // matches entries with column "name" not being "Demo"
```

A tilde ("~") at the start of a filter rule indicates a regular expression. The actual regular expression has to be
written using the re2 syntax used by Go (see https://github.com/google/re2/wiki/Syntax).

Additional rule options for integers, floats and strings are `>`, `>=`, `<` and `<=`, e.g.:

```
filter.FilterEntries(columnMap, events, []string{"pid:>=55"})
```

## Optimizing / Streaming

If you have to filter a stream of incoming events, you can use

```
myFilter := filter.GetFilterFromString(columnMap, filter)
```

to get a filter with a .Match(entry) function that you can use to match against entries.

## TODO / TBD

* Maybe use a custom type instead of []string that can be easily created with filter.FilterRules("rule1", "rule2") or
  so.
* Make GetFilterFromString also accept multiple filters and return a combined matcher.