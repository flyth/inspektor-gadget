# Filter Offloading System

This package demonstrates a mechanism for offloading parts of filter expressions to kernel space using eBPF programs.

## Overview

The filter offloading system allows for processing filter expressions like `pid == 1 || otherVal == 2` and determining which parts can be offloaded to the kernel space. This is particularly useful for performance optimization, as filtering in the kernel can significantly reduce the amount of data that needs to be processed in user space.

## Key Components

### Constraints

The system defines several types of constraints that can be offloaded:

- **EqualsConstraint**: For exact value matches (`field == value`)
- **RangeConstraint**: For value ranges (`field > min && field < max`)
- **SetConstraint**: For multiple possible values (`field == value1 || field == value2`)

Each constraint type implements the `Constraint` interface which provides methods for:
- Getting the constraint's name (the field it applies to)
- Getting the constraint's type
- Merging with other constraints

### Offloaders

Offloaders are responsible for determining if a specific constraint can be offloaded and for activating the offloading when needed. Each offloader provides:

- A `CheckCallback` that determines if a constraint can be offloaded
- An `OffloadCallback` that activates the offloading mechanism

The system currently includes two example offloaders:
- **ContainerOffloader**: For filtering container IDs
- **ParamOffloader**: For filtering process IDs (PIDs)

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
3. Use the `OffloadPatcher` to process your filter expression
4. Apply the modified filter in user space, with the offloadable parts handled in kernel space

```go
// Example usage
ctx := context.Background()
patcher := NewOffloadPatcher()
patcher.RegisterOffloader("container", ContainerOffloader())
patcher.RegisterOffloader("pid", ParamOffloader())

// Process AST nodes with the patcher
Walk(&tree.Node, patcher)
```

## Example

The `main.go` file includes examples of different filter expressions and demonstrates how the system processes them.

## Extending

To add support for new fields or constraint types:

1. Create a new offloader for your field using the `ConstraintHandler` utilities
2. Register your offloader with the `OffloadPatcher`

```go
// Example offloader with constraint utilities
func MyOffloader() *OffloadInfo {
    // Create a constraint handler
    handler := NewConstraintHandler("myfield").WithMaxSetSize(10)

    return &OffloadInfo{
        Name: "myfield",
        // Use generic constraint checking
        CheckCallback: func(c any) (bool, error) {
            return handler.CheckGenericConstraint(c)
        },
        OffloadCallback: func(ctx context.Context, c any) (bool, error) {
            switch constraint := c.(type) {
            case *EqualsConstraint:
                // For string fields
                return handler.ActivateStringEqualsConstraint(ctx, constraint,
                    func(ctx context.Context, value string) (bool, error) {
                        // Actual activation code
                        return true, nil
                    })

                // For numeric fields
                // return handler.ActivateNumericEqualsConstraint(ctx, constraint,
                //    func(ctx context.Context, value int64) (bool, error) {
                //        // Actual activation code
                //        return true, nil
                //    })

            case *SetConstraint:
                // Similar helpers exist for sets
                // ...

            case *RangeConstraint:
                // And for ranges
                // ...
            }
            return false, fmt.Errorf("unsupported constraint type")
        },
    }
}
```

For more complex constraint types, you may need to extend the `Constraint` interface and add appropriate handling in the `IsOffloadable` method.

## Generic Numeric Handling

The system now uses generics to handle different numeric types, making it easier to support various integer and floating-point values. The `numeric.go` utility provides:

- Type-safe numeric comparisons across different types
- Range checking for any numeric value
- Automatic type conversion for constraint operations

This simplifies the implementation of offloaders that need to handle numeric constraints.

## Constraint Handling Utilities

The `ConstraintHandler` provides a set of utilities that make it easier to implement offloaders with proper type handling:

### Creating Handlers

```go
// Create a basic handler
handler := NewConstraintHandler("myoffloader")

// Configure maximum set size
handler := NewConstraintHandler("myoffloader").WithMaxSetSize(20)
```

### Constraint Checking

The handler provides generic constraint checking that works for most use cases:

```go
// In your CheckCallback
return handler.CheckGenericConstraint(constraint)
```

### Type-Safe Value Extraction

The handler provides helpers to safely extract typed values:

```go
// Get a string value
strValue, ok := handler.GetStringValue(constraint.Value)

// Get a numeric value as int64
numValue, ok := handler.GetNumericValue(constraint.Value)
```

### Constraint Activation

Type-specific helpers for activating different constraint types:

```go
// For string equals constraints
handler.ActivateStringEqualsConstraint(ctx, constraint, 
    func(ctx context.Context, value string) (bool, error) {
        // Your string-specific implementation
        return true, nil
    })

// For numeric equals constraints
handler.ActivateNumericEqualsConstraint(ctx, constraint, 
    func(ctx context.Context, value int64) (bool, error) {
        // Your numeric-specific implementation
        return true, nil
    })

// For numeric range constraints
handler.ActivateNumericRangeConstraint(ctx, constraint, 
    func(ctx context.Context, min, max *int64) (bool, error) {
        // Your range-specific implementation
        return true, nil
    })

// For string set constraints
handler.ActivateStringSetConstraint(ctx, constraint, 
    func(ctx context.Context, values []string) (bool, error) {
        // Your set-specific implementation
        return true, nil
    })
```

This approach lets you focus on the actual offloading logic without worrying about type conversions and error handling.

## Debugging and Logging

The system provides extensive logging to help debug offloading decisions:

### Log Format

The logging system uses prefixes to indicate the nature of messages:

- `CHECKING`: Indicates the system is evaluating a node or constraint
- `PROCESSING`: Shows detailed steps in processing a node
- `IDENTIFIED`: Reports successful identification of components
- `CREATED`: Indicates a new constraint has been created
- `ATTEMPTING`: Shows the system is trying to perform an operation
- `OFFLOAD FAILED`: Provides information about why offloading was not possible
- `❌`: Indicates a failure or rejection
- `✅`: Indicates a success or acceptance

### What Gets Logged

1. **AST Node Processing**: Each node in the AST is logged as it's processed
2. **Constraint Evaluation**: The system logs details about each constraint and whether it can be offloaded
3. **Offloader Decisions**: Each offloader logs its decision process and reasons for accepting or rejecting constraints
4. **Merging Operations**: When constraints need to be merged (in AND operations), the process and results are logged
5. **Activation Results**: The system logs which offloaders were successfully activated

### Using the Logs

When offloading isn't working as expected, examine the logs to identify:

- Which part of the filter expression couldn't be offloaded and why
- Whether the constraints were recognized but rejected by the offloaders
- If constraints couldn't be merged when using logical operators
- Whether offloader activation succeeded after constraint checking

The test cases in `main.go` demonstrate the logging system with various filter expressions.
