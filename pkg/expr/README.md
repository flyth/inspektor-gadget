# Filter Offloading System

This package provides a mechanism for offloading parts of filter expressions to kernel space using eBPF programs.

## Overview

The filter offloading system allows for processing filter expressions like `pid == 1 || otherVal == 2` and determining which parts can be offloaded to the kernel space. This is particularly useful for performance optimization, as filtering in the kernel can significantly reduce the amount of data that needs to be processed in user space.

## Key Components

### Constraints

The system defines several types of constraints that can be offloaded:

- **EqualsConstraint**: For exact value matches (`field == value`)
- **RangeConstraint**: For value ranges (`field > min && field < max`)
- **SetConstraint**: For multiple possible values (`field == value1 || field == value2`)
- **StringFunctionConstraint**: For string function operations (`field.startsWith("prefix")`, `field.endsWith("suffix")`, `field.contains("substring")`)

Each constraint type implements the `Constraint` interface which provides methods for:
- Getting the constraint's name (the field it applies to)
- Getting the constraint's type
- Merging with other constraints

### Offloaders

Offloaders are responsible for determining if a specific constraint can be offloaded and for activating the offloading when needed. Each offloader provides:

- A `CheckCallback` that determines if a constraint can be offloaded
- An `OffloadCallback` that activates the offloading mechanism

The package includes example offloaders in `offloader_example.go`:
- **NamespaceOffloader**: For filtering namespace values
- **PortOffloader**: For filtering port numbers

### AST Processing

The system processes the Abstract Syntax Tree (AST) of the filter expression to:

1. Identify comparison operations that could be offloaded
2. Check if the offloaders support these operations
3. Replace supported operations with `true` in the AST, as they will be handled by the kernel

## Logical Operations

The system handles logical operations (AND, OR) carefully:

- For `OR` operations:
  - Both sides must target the same field (e.g., `container == 'a' || container == 'b'`)
  - For equality constraints, these are combined into a set constraint
  - For range constraints on PIDs, the system supports special multi-range offloading (e.g., `pid < 100 || pid > 1000`)
- For `AND` operations:
  - If both constraints target different fields, both can be offloaded independently
  - If both target the same field, they must be mergeable (e.g., `pid > 10 && pid < 20`)
  - If the constraints are contradictory (e.g., `pid < 10 && pid > 20`), offloading is not possible

## Usage

To use the filter offloading system:

1. Create an `OffloadPatcher` using the `NewOffloadPatcher()` constructor
2. Register offloaders for the fields you want to support
3. Use the `Compile` function to process your filter expression
4. Apply the modified filter in user space, with the offloadable parts handled in kernel space

```go
// Example usage
ctx := context.Background()
patcher := expr.NewOffloadPatcher()
patcher.RegisterOffloader("container", ContainerOffloader())
patcher.RegisterOffloader("pid", ParamOffloader())
patcher.RegisterOffloader("command", StringFunctionOffloader("command"))

// Create a datasource patcher (from your datasource)
dsp := datasource.DSPatcher{
    Datasource: ds,
}

// Get expression options
options := datasource.GetBuiltInExpressions()
options = append(options, expr2.AsBool(), expr2.Env(datasource.Data(nil)))

// Compile the filter with offloading - supports various constraint types
program, err := expr.Compile("container == 'a' || pid == 1 || command.startsWith('test')", patcher, dsp, options...)
if err != nil {
    // Handle error
}

// Use the compiled program
```

## Extending

To add support for new fields or constraint types:

1. Create a new offloader for your field using the `ConstraintHandler` utilities
2. Register your offloader with the `OffloadPatcher`

```go
// Example offloader with constraint utilities
func MyOffloader() *expr.OffloadInfo {
    // Create a constraint handler
    handler := expr.NewConstraintHandler("myfield").WithMaxSetSize(10)

    return &expr.OffloadInfo{
        Name: "myfield",
        // Use generic constraint checking
        CheckCallback: func(c any) (bool, error) {
            return handler.CheckGenericConstraint(c)
        },
        OffloadCallback: func(ctx context.Context, c any) (bool, error) {
            switch constraint := c.(type) {
            case *expr.EqualsConstraint:
                // For string fields
                return handler.ActivateStringEqualsConstraint(ctx, constraint,
                    func(ctx context.Context, value string) (bool, error) {
                        // Actual activation code
                        return true, nil
                    })
            }
            return false, fmt.Errorf("unsupported constraint type")
        },
    }
}
```

## String Function Constraints

The system supports string function constraints for operations like `startsWith`, `endsWith`, and `contains`. This allows for more expressive filtering on string fields:

```go
// Examples of supported string function expressions
"field.startsWith('prefix')"    // Field starts with a specific prefix
"field.endsWith('suffix')"      // Field ends with a specific suffix
"field.contains('substring')"   // Field contains a specific substring
```

These constraints can be combined with other constraint types using logical operators:

```go
// Combining string functions with other constraints
"field.startsWith('prefix') && otherField > 10"
"field.contains('substring') || field == 'exact'"
```

To enable string function constraints, register a `StringFunctionOffloader` for your string fields:

```go
// Register a string function offloader
patcher.RegisterOffloader("command", StringFunctionOffloader("command"))
```

## Generic Numeric Handling

The system uses generics to handle different numeric types, making it easier to support various integer and floating-point values. The numeric utilities provide:

- Type-safe numeric comparisons across different types
- Range checking for any numeric value
- Automatic type conversion for constraint operations

## Constraint Handling Utilities

The `ConstraintHandler` provides a set of utilities that make it easier to implement offloaders with proper type handling:

### Creating Handlers

```go
// Create a basic handler
handler := expr.NewConstraintHandler("myoffloader")

// Configure maximum set size
handler := expr.NewConstraintHandler("myoffloader").WithMaxSetSize(20)
```

### Type-Safe Value Extraction

```go
// Get a string value
strValue, ok := handler.GetStringValue(constraint.Value)

// Get a numeric value as int64
numValue, ok := handler.GetNumericValue(constraint.Value)
```

### Constraint Activation

```go
// For string equals constraints
handler.ActivateStringEqualsConstraint(ctx, constraint, 
    func(ctx context.Context, value string) (bool, error) {
        // Your string-specific implementation
        return true, nil
    })

// For numeric range constraints
handler.ActivateNumericRangeConstraint(ctx, constraint, 
    func(ctx context.Context, min, max *int64) (bool, error) {
        // Your range-specific implementation
        return true, nil
    })
```
