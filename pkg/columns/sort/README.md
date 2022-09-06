# Sorting

This package can be used to sort an array of structs that you have a `Columns` instance of.

Calling

```
sort.SortEntries(columnMap, entries, []string{"node", "-time"})
```

for example sorts the array by the time column in descending order and afterwards by the node column.
The "-" prefix means the sorter should use descending order. Sorting by multiple fields will be done from the last field
to the first in a stable way - so the first column always gets the highest priority.

