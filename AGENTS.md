# Development Guidelines for Go

## Core Philosophy

**TEST-DRIVEN DEVELOPMENT IS NON-NEGOTIABLE.** Every single line of production code must be written in response to a failing test. No exceptions. This is not a suggestion or a preference - it is the fundamental practice that enables all other principles in this document.

I follow Test-Driven Development (TDD) with a strong emphasis on behavior-driven testing and Go's idiomatic patterns. All work should be done in small, incremental changes that maintain a working state throughout development.

## Quick Reference

**Key Principles:**

- Write tests first (TDD)
- Test behavior, not implementation
- Follow Go idioms and conventions
- Small, focused functions
- Explicit error handling
- Use real types in tests, never redefine them

**Preferred Tools:**

- **Language**: Go (latest stable version)
- **Testing**: Standard `testing` package + testify/assert for assertions
- **Code Quality**: `go fmt`, `go vet`, `golangci-lint`

## Testing Principles

### Behavior-Driven Testing

- **No "unit tests"** - this term is not helpful. Tests should verify expected behavior, treating implementation as a black box
- Test through the public API exclusively - internals should be invisible to tests
- No 1:1 mapping between test files and implementation files
- Tests that examine internal implementation details are wasteful and should be avoided
- **Coverage targets**: 100% coverage should be expected at all times, but these tests must ALWAYS be based on business behaviour, not implementation details
- Tests must document expected business behaviour

### Testing Tools

- **Standard `testing` package** for test framework
- **testify/assert** for readable assertions (optional but recommended)
- **testify/mock** for mocking when needed
- **httptest** for HTTP handler testing
- All test code must follow the same Go conventions as production code

### Test Organization

```
internal/
  payment/
    processor.go
    validator.go
    processor_test.go  // The validator is an implementation detail. Validation is fully covered, but by testing the expected business behaviour
```

### Test Data Pattern

Use factory functions with optional overrides for test data:

```go
type PaymentRequest struct {
    CardAccountID    string
    Amount          decimal.Decimal
    Source          string
    AccountStatus   string
    LastName        string
    DateOfBirth     string
    CardDetails     PayingCardDetails
    AddressDetails  AddressDetails
    Brand           string
}

type PayingCardDetails struct {
    CVV   string
    Token string
}

type AddressDetails struct {
    HouseNumber   string
    HouseName     string
    AddressLine1  string
    AddressLine2  string
    City          string
    Postcode      string
}

func NewMockPaymentRequest(overrides ...func(*PaymentRequest)) PaymentRequest {
    req := PaymentRequest{
        CardAccountID:  "1234567890123456",
        Amount:         decimal.NewFromInt(100),
        Source:         "Web",
        AccountStatus:  "Normal",
        LastName:       "Doe",
        DateOfBirth:    "1980-01-01",
        CardDetails:    NewMockCardDetails(),
        AddressDetails: NewMockAddressDetails(),
        Brand:          "Visa",
    }
    
    for _, override := range overrides {
        override(&req)
    }
    
    return req
}

func NewMockCardDetails(overrides ...func(*PayingCardDetails)) PayingCardDetails {
    details := PayingCardDetails{
        CVV:   "123",
        Token: "token123",
    }
    
    for _, override := range overrides {
        override(&details)
    }
    
    return details
}

func NewMockAddressDetails(overrides ...func(*AddressDetails)) AddressDetails {
    details := AddressDetails{
        HouseNumber:  "123",
        HouseName:    "Test House",
        AddressLine1: "Test Address Line 1",
        AddressLine2: "Test Address Line 2",
        City:         "Test City",
        Postcode:     "SW1A 1AA",
    }
    
    for _, override := range overrides {
        override(&details)
    }
    
    return details
}

// Usage in tests:
func TestPaymentProcessing(t *testing.T) {
    req := NewMockPaymentRequest(func(r *PaymentRequest) {
        r.Amount = decimal.NewFromInt(50)
        r.CardDetails.CVV = "456"
    })
    
    // test with customized request...
}
```

Key principles:

- Always return complete structs with sensible defaults
- Accept variadic override functions for customization
- Build incrementally - extract nested struct factories as needed
- Compose factories for complex objects

## Go Guidelines

### Idiomatic Go

- Follow `gofmt` formatting always
- Use `go vet` and `golangci-lint` for static analysis
- Follow Go naming conventions (CamelCase for exported, camelCase for unexported)
- Use receiver names consistently (single letter or short abbreviation)
- Prefer composition over inheritance
- Handle errors explicitly, don't ignore them

### Error Handling

Go's explicit error handling is a feature, not a bug. Embrace it:

```go
// Good - Explicit error handling
func ProcessPayment(req PaymentRequest) (ProcessedPayment, error) {
    if err := validatePaymentAmount(req.Amount); err != nil {
        return ProcessedPayment{}, fmt.Errorf("invalid amount: %w", err)
    }
    
    if err := validateCardDetails(req.CardDetails); err != nil {
        return ProcessedPayment{}, fmt.Errorf("invalid card details: %w", err)
    }
    
    payment, err := executePayment(req)
    if err != nil {
        return ProcessedPayment{}, fmt.Errorf("payment execution failed: %w", err)
    }
    
    return payment, nil
}

// Create custom error types for different error categories
type ValidationError struct {
    Field   string
    Message string
}

func (e ValidationError) Error() string {
    return fmt.Sprintf("validation failed for %s: %s", e.Field, e.Message)
}

// Use errors.Is and errors.As for error checking
func handlePaymentError(err error) {
    var validationErr ValidationError
    if errors.As(err, &validationErr) {
        // Handle validation error specifically
        log.Printf("Validation error in field %s: %s", validationErr.Field, validationErr.Message)
        return
    }
    
    // Handle other errors
    log.Printf("Payment processing error: %v", err)
}
```

### Type Definitions

```go
// Good - Clear, descriptive types
type UserID string
type PaymentAmount decimal.Decimal
type EmailAddress string

// Use type constraints for additional safety
type PaymentStatus string

const (
    PaymentStatusPending   PaymentStatus = "pending"
    PaymentStatusCompleted PaymentStatus = "completed"
    PaymentStatusFailed    PaymentStatus = "failed"
)

// Struct definitions should be clear and focused
type Payment struct {
    ID          PaymentID
    UserID      UserID
    Amount      PaymentAmount
    Status      PaymentStatus
    ProcessedAt time.Time
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

// Use embedding for composition
type AuditableEntity struct {
    CreatedAt time.Time
    UpdatedAt time.Time
    CreatedBy UserID
    UpdatedBy UserID
}

type Payment struct {
    ID     PaymentID
    UserID UserID
    Amount PaymentAmount
    Status PaymentStatus
    AuditableEntity
}
```

### Validation with Custom Types

```go
// Define validation interfaces
type Validator interface {
    Validate() error
}

// Implement validation on types
func (p PaymentRequest) Validate() error {
    if p.Amount.LessThanOrEqual(decimal.Zero) {
        return ValidationError{
            Field:   "Amount",
            Message: "must be greater than zero",
        }
    }
    
    if p.Amount.GreaterThan(decimal.NewFromInt(10000)) {
        return ValidationError{
            Field:   "Amount", 
            Message: "must not exceed £10,000",
        }
    }
    
    if err := p.CardDetails.Validate(); err != nil {
        return fmt.Errorf("card details: %w", err)
    }
    
    return nil
}

func (c PayingCardDetails) Validate() error {
    cvvRegex := regexp.MustCompile(`^\d{3,4}$`)
    if !cvvRegex.MatchString(c.CVV) {
        return ValidationError{
            Field:   "CVV",
            Message: "must be 3 or 4 digits",
        }
    }
    
    if len(strings.TrimSpace(c.Token)) == 0 {
        return ValidationError{
            Field:   "Token",
            Message: "cannot be empty",
        }
    }
    
    return nil
}
```

#### Schema Usage in Tests

**CRITICAL**: Tests must use real types from the main project, not redefine their own.

```go
// ❌ WRONG - Defining types in test files
type Project struct {
    ID          string
    WorkspaceID string
    OwnerID     *string
    Name        string
    CreatedAt   time.Time
    UpdatedAt   time.Time
}

// ✅ CORRECT - Import types from the shared package
import "github.com/your-org/project/internal/types"

func TestProjectCreation(t *testing.T) {
    project := types.Project{
        ID:          "proj_123",
        WorkspaceID: "ws_456", 
        OwnerID:     stringPtr("user_789"),
        Name:        "Test Project",
        CreatedAt:   time.Now(),
        UpdatedAt:   time.Now(),
    }
    
    // test logic...
}
```

**Why this matters:**

- **Type Safety**: Ensures tests use the same types as production code
- **Consistency**: Changes to types automatically propagate to tests  
- **Maintainability**: Single source of truth for data structures
- **Prevents Drift**: Tests can't accidentally diverge from real types

## Code Style

### Go Idioms

- Use short variable names for short scopes (`i` for index, `err` for error, `ctx` for context)
- Use longer, descriptive names for longer scopes
- Prefer `if err != nil` checks immediately after function calls
- Use early returns to reduce nesting
- Group related functionality in packages, not in large structs

#### Examples of Idiomatic Patterns

```go
// Good - Early returns reduce nesting
func ProcessOrder(order Order) (ProcessedOrder, error) {
    if err := order.Validate(); err != nil {
        return ProcessedOrder{}, fmt.Errorf("invalid order: %w", err)
    }
    
    total := calculateTotal(order.Items)
    shipping := calculateShipping(total)
    
    processedOrder := ProcessedOrder{
        Order:        order,
        Total:        total,
        ShippingCost: shipping,
        ProcessedAt:  time.Now(),
    }
    
    return processedOrder, nil
}

// Good - Composition with interfaces
type PaymentProcessor interface {
    ProcessPayment(ctx context.Context, req PaymentRequest) (Payment, error)
}

type OrderService struct {
    paymentProcessor PaymentProcessor
    logger          *slog.Logger
}

func (s OrderService) CompleteOrder(ctx context.Context, order Order) error {
    payment, err := s.paymentProcessor.ProcessPayment(ctx, order.PaymentRequest)
    if err != nil {
        s.logger.Error("payment processing failed", "order_id", order.ID, "error", err)
        return fmt.Errorf("failed to process payment: %w", err)
    }
    
    s.logger.Info("order completed", "order_id", order.ID, "payment_id", payment.ID)
    return nil
}

// Good - Using context appropriately
func (s OrderService) ProcessOrderWithTimeout(order Order) error {
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    return s.CompleteOrder(ctx, order)
}
```

### Code Structure

- **Use early returns** to reduce nesting
- **Avoid deep nesting** in general (max 2 levels)
- Keep functions small and focused on a single responsibility
- Prefer flat, readable code over clever abstractions
- Use interfaces to define behavior, structs to define data

### Naming Conventions

- **Functions**: `CamelCase` for exported, `camelCase` for unexported
- **Types**: `CamelCase` (e.g., `PaymentRequest`, `UserProfile`)
- **Constants**: `CamelCase` or `UPPER_SNAKE_CASE` for package-level constants
- **Files**: `snake_case.go` for all Go files
- **Test files**: `*_test.go`
- **Packages**: short, lowercase, no underscores

### No Comments in Code

Code should be self-documenting through clear naming and structure. Comments indicate that the code itself is not clear enough.

```go
// Avoid: Comments explaining what the code does
func calculateDiscount(price decimal.Decimal, customer Customer) decimal.Decimal {
    // Check if customer is premium
    if customer.Tier == "premium" {
        // Apply 20% discount for premium customers  
        return price.Mul(decimal.NewFromFloat(0.8))
    }
    // Regular customers get 10% discount
    return price.Mul(decimal.NewFromFloat(0.9))
}

// Good: Self-documenting code with clear names
const (
    PremiumDiscountMultiplier  = 0.8
    StandardDiscountMultiplier = 0.9
)

func isPremiumCustomer(customer Customer) bool {
    return customer.Tier == "premium"
}

func calculateDiscount(price decimal.Decimal, customer Customer) decimal.Decimal {
    var multiplier float64
    if isPremiumCustomer(customer) {
        multiplier = PremiumDiscountMultiplier
    } else {
        multiplier = StandardDiscountMultiplier
    }
    
    return price.Mul(decimal.NewFromFloat(multiplier))
}
```

**Exception**: Godoc comments for exported functions, types, and packages are required and should explain the behavior and usage.

```go
// ProcessPayment validates the payment request and processes the payment.
// It returns a ProcessedPayment on success or an error if validation fails
// or payment processing encounters an issue.
func ProcessPayment(req PaymentRequest) (ProcessedPayment, error) {
    // implementation
}
```

### Prefer Option Structs

Use option structs for function parameters when you have multiple optional parameters:

```go
// Avoid: Multiple optional parameters  
func CreatePayment(amount decimal.Decimal, currency string, cardID string, 
    customerID string, description *string, metadata map[string]interface{},
    idempotencyKey *string) (Payment, error) {
    // implementation
}

// Calling it is unclear
payment, err := CreatePayment(
    decimal.NewFromInt(100),
    "GBP", 
    "card_123",
    "cust_456",
    nil,
    map[string]interface{}{"orderId": "order_789"},
    stringPtr("key_123"),
)

// Good: Options struct with clear property names
type CreatePaymentOptions struct {
    Amount         decimal.Decimal
    Currency       string
    CardID         string
    CustomerID     string
    Description    *string
    Metadata       map[string]interface{}
    IdempotencyKey *string
}

func CreatePayment(opts CreatePaymentOptions) (Payment, error) {
    // implementation with opts.Amount, opts.Currency, etc.
}

// Clear and readable at call site
payment, err := CreatePayment(CreatePaymentOptions{
    Amount:         decimal.NewFromInt(100),
    Currency:       "GBP",
    CardID:         "card_123", 
    CustomerID:     "cust_456",
    Metadata:       map[string]interface{}{"orderId": "order_789"},
    IdempotencyKey: stringPtr("key_123"),
})

// For complex configuration
type ProcessOrderOptions struct {
    Order    Order
    Shipping ShippingOptions
    Payment  PaymentOptions
}

type ShippingOptions struct {
    Method  string
    Address Address
}

type PaymentOptions struct {
    Method      PaymentMethod
    SaveForFuture bool
}

func ProcessOrder(opts ProcessOrderOptions) (ProcessedOrder, error) {
    // Clear access to nested options
    if opts.Payment.SaveForFuture {
        // save payment method logic
    }
    
    return executeOrder(opts.Order, opts.Shipping.Method)
}

// Acceptable: Single parameter for simple functions
func Double(n int) int { return n * 2 }
func GetName(user User) string { return user.Name }

// Acceptable: Well-established patterns
numbers := []int{1, 2, 3}
doubled := make([]int, len(numbers))
for i, n := range numbers {
    doubled[i] = n * 2
}
```

**Guidelines for option structs:**

- Use for functions with multiple parameters (especially optional ones)
- Group related options together (shipping, payment, etc.)
- Provide validation methods on option structs when needed
- Consider using functional options pattern for very complex cases

**When positional parameters are acceptable:**

- Single-parameter functions
- Functions with 2-3 parameters where order is conventional
- Mathematical operations where parameter order is obvious

## Development Workflow

### TDD Process - THE FUNDAMENTAL PRACTICE

**CRITICAL**: TDD is not optional. Every feature, every bug fix, every change MUST follow this process:

Follow Red-Green-Refactor strictly:

1. **Red**: Write a failing test for the desired behavior. NO PRODUCTION CODE until you have a failing test.
2. **Green**: Write the MINIMUM code to make the test pass. Resist the urge to write more than needed.
3. **Refactor**: Assess the code for improvement opportunities. If refactoring would add value, clean up the code while keeping tests green. If the code is already clean and expressive, move on.

**Common TDD Violations to Avoid:**

- Writing production code without a failing test first
- Writing multiple tests before making the first one pass
- Writing more production code than needed to pass the current test
- Skipping the refactor assessment step when code could be improved
- Adding functionality "while you're there" without a test driving it

**Remember**: If you're typing production code and there isn't a failing test demanding that code, you're not doing TDD.

#### TDD Example Workflow

```go
// Step 1: Red - Start with the simplest behavior
func TestOrderProcessing_CalculatesTotalWithShipping(t *testing.T) {
    order := NewMockOrder(func(o *Order) {
        o.Items = []OrderItem{{Price: decimal.NewFromInt(30), Quantity: 1}}
        o.ShippingCost = decimal.NewFromFloat(5.99)
    })
    
    processed, err := ProcessOrder(order)
    
    require.NoError(t, err)
    assert.Equal(t, decimal.NewFromFloat(35.99), processed.Total)
    assert.Equal(t, decimal.NewFromFloat(5.99), processed.ShippingCost)
}

// Step 2: Green - Minimal implementation
func ProcessOrder(order Order) (ProcessedOrder, error) {
    var itemsTotal decimal.Decimal
    for _, item := range order.Items {
        itemsTotal = itemsTotal.Add(item.Price.Mul(decimal.NewFromInt(int64(item.Quantity))))
    }
    
    return ProcessedOrder{
        Order:        order,
        ShippingCost: order.ShippingCost,
        Total:        itemsTotal.Add(order.ShippingCost),
    }, nil
}

// Step 3: Red - Add test for free shipping behavior
func TestOrderProcessing_AppliesFreeShippingOver50(t *testing.T) {
    order := NewMockOrder(func(o *Order) {
        o.Items = []OrderItem{{Price: decimal.NewFromInt(60), Quantity: 1}}
        o.ShippingCost = decimal.NewFromFloat(5.99)
    })
    
    processed, err := ProcessOrder(order)
    
    require.NoError(t, err)
    assert.Equal(t, decimal.Zero, processed.ShippingCost)
    assert.Equal(t, decimal.NewFromInt(60), processed.Total)
}

// Step 4: Green - NOW we can add the conditional because both paths are tested
func ProcessOrder(order Order) (ProcessedOrder, error) {
    var itemsTotal decimal.Decimal
    for _, item := range order.Items {
        itemsTotal = itemsTotal.Add(item.Price.Mul(decimal.NewFromInt(int64(item.Quantity))))
    }
    
    var shippingCost decimal.Decimal
    if itemsTotal.GreaterThan(decimal.NewFromInt(50)) {
        shippingCost = decimal.Zero
    } else {
        shippingCost = order.ShippingCost
    }
    
    return ProcessedOrder{
        Order:        order,
        ShippingCost: shippingCost,
        Total:        itemsTotal.Add(shippingCost),
    }, nil
}

// Step 5: Refactor - Extract constants and improve readability
const FreeShippingThreshold = 50

func calculateItemsTotal(items []OrderItem) decimal.Decimal {
    var total decimal.Decimal
    for _, item := range items {
        total = total.Add(item.Price.Mul(decimal.NewFromInt(int64(item.Quantity))))
    }
    return total
}

func qualifiesForFreeShipping(itemsTotal decimal.Decimal) bool {
    return itemsTotal.GreaterThan(decimal.NewFromInt(FreeShippingThreshold))
}

func ProcessOrder(order Order) (ProcessedOrder, error) {
    itemsTotal := calculateItemsTotal(order.Items)
    
    var shippingCost decimal.Decimal
    if qualifiesForFreeShipping(itemsTotal) {
        shippingCost = decimal.Zero
    } else {
        shippingCost = order.ShippingCost
    }
    
    return ProcessedOrder{
        Order:        order,
        ShippingCost: shippingCost,
        Total:        itemsTotal.Add(shippingCost),
    }, nil
}
```

### Refactoring - The Critical Third Step

Evaluating refactoring opportunities is not optional - it's the third step in the TDD cycle. After achieving a green state and committing your work, you MUST assess whether the code can be improved. However, only refactor if there's clear value - if the code is already clean and expresses intent well, move on to the next test.

#### When to Refactor

- **Always assess after green**: Once tests pass, before moving to the next test, evaluate if refactoring would add value
- **When you see duplication**: But understand what duplication really means (see DRY below)
- **When names could be clearer**: Variable names, function names, or type names that don't clearly express intent
- **When structure could be simpler**: Complex conditional logic, deeply nested code, or long functions
- **When patterns emerge**: After implementing several similar features, useful abstractions may become apparent

**Remember**: Not all code needs refactoring. If the code is already clean, expressive, and well-structured, commit and move on.

#### Understanding DRY in Go

DRY (Don't Repeat Yourself) is about not duplicating **knowledge** in the system, not about eliminating all code that looks similar.

```go
// This is NOT a DRY violation - different knowledge despite similar code
func validateUserAge(age int) error {
    if age < 18 || age > 100 {
        return ValidationError{Field: "age", Message: "must be between 18 and 100"}
    }
    return nil
}

func validateProductRating(rating int) error {
    if rating < 1 || rating > 5 {
        return ValidationError{Field: "rating", Message: "must be between 1 and 5"}
    }
    return nil
}

func validateYearsOfExperience(years int) error {
    if years < 0 || years > 50 {
        return ValidationError{Field: "experience", Message: "must be between 0 and 50"}
    }
    return nil
}

// These functions have similar structure (checking numeric ranges), but they
// represent completely different business rules

// This IS a DRY violation - same knowledge in multiple places
const FreeShippingThreshold = 50  // Knowledge duplicated across functions!

func (o Order) CalculateTotal() decimal.Decimal {
    itemsTotal := o.calculateItemsTotal()
    if itemsTotal.GreaterThan(decimal.NewFromInt(50)) { // Same knowledge!
        return itemsTotal
    }
    return itemsTotal.Add(o.ShippingCost)
}

func (o Order) GetShippingCost() decimal.Decimal {
    itemsTotal := o.calculateItemsTotal()
    if itemsTotal.GreaterThan(decimal.NewFromInt(50)) { // Same knowledge again!
        return decimal.Zero
    }
    return o.ShippingCost
}

// Refactored - knowledge in one place
const FreeShippingThreshold = 50

func qualifiesForFreeShipping(itemsTotal decimal.Decimal) bool {
    return itemsTotal.GreaterThan(decimal.NewFromInt(FreeShippingThreshold))
}

func (o Order) CalculateTotal() decimal.Decimal {
    itemsTotal := o.calculateItemsTotal()
    if qualifiesForFreeShipping(itemsTotal) {
        return itemsTotal
    }
    return itemsTotal.Add(o.ShippingCost)
}

func (o Order) GetShippingCost() decimal.Decimal {
    itemsTotal := o.calculateItemsTotal()
    if qualifiesForFreeShipping(itemsTotal) {
        return decimal.Zero
    }
    return o.ShippingCost
}
```

### Commit Guidelines

- Each commit should represent a complete, working change
- Use conventional commits format:
  ```
  feat: add payment validation
  fix: correct date formatting in payment processor
  refactor: extract payment validation logic
  test: add edge cases for payment validation
  ```
- Include test changes with feature changes in the same commit

### Pull Request Standards

- Every PR must have all tests passing
- All linting and quality checks must pass (`go fmt`, `go vet`, `golangci-lint`)
- Work in small increments that maintain a working state
- PRs should be focused on a single feature or fix
- Include description of the behavior change, not implementation details

## Working with Claude

### Expectations

When working with my code:

1. **ALWAYS FOLLOW TDD** - No production code without a failing test. This is not negotiable.
2. **Think deeply** before making any edits
3. **Understand the full context** of the code and requirements
4. **Ask clarifying questions** when requirements are ambiguous
5. **Think from first principles** - don't make assumptions
6. **Assess refactoring after every green** - Look for opportunities to improve code structure, but only refactor if it adds value
7. **Keep project docs current** - update them whenever you introduce meaningful changes

### Code Changes

When suggesting or making changes:

- **Start with a failing test** - always. No exceptions.
- After making tests pass, always assess refactoring opportunities (but only refactor if it adds value)
- After refactoring, verify all tests and static analysis pass, then commit
- Respect the existing patterns and conventions
- Maintain test coverage for all behavior changes
- Keep changes small and incremental
- Ensure all Go best practices are followed
- Provide rationale for significant design decisions

**If you find yourself writing production code without a failing test, STOP immediately and write the test first.**

### Communication

- Be explicit about trade-offs in different approaches
- Explain the reasoning behind significant design decisions
- Flag any deviations from these guidelines with justification
- Suggest improvements that align with these principles
- When unsure, ask for clarification rather than assuming

## Example Patterns

### Error Handling

```go
// Good - Custom error types with context
type PaymentError struct {
    Code    string
    Message string
    Cause   error
}

func (e PaymentError) Error() string {
    if e.Cause != nil {
        return fmt.Sprintf("payment error [%s]: %s: %v", e.Code, e.Message, e.Cause)
    }
    return fmt.Sprintf("payment error [%s]: %s", e.Code, e.Message)
}

func (e PaymentError) Unwrap() error {
    return e.Cause
}

func ProcessPayment(req PaymentRequest) (ProcessedPayment, error) {
    if err := req.Validate(); err != nil {
        return ProcessedPayment{}, PaymentError{
            Code:    "VALIDATION_FAILED",
            Message: "request validation failed",
            Cause:   err,
        }
    }
    
    if !hasSufficientFunds(req) {
        return ProcessedPayment{}, PaymentError{
            Code:    "INSUFFICIENT_FUNDS", 
            Message: "account has insufficient funds",
        }
    }
    
    payment, err := executePayment(req)
    if err != nil {
        return ProcessedPayment{}, PaymentError{
            Code:    "EXECUTION_FAILED",
            Message: "payment execution failed", 
            Cause:   err,
        }
    }
    
    return payment, nil
}
```

### Testing Behavior

```go
// Good - tests behavior through public API
func TestPaymentProcessor_DeclinePaymentWhenInsufficientFunds(t *testing.T) {
    req := NewMockPaymentRequest(func(r *PaymentRequest) {
        r.Amount = decimal.NewFromInt(1000)
    })
    
    // This would typically be mocked or use a test database
    account := NewMockAccount(func(a *Account) {
        a.Balance = decimal.NewFromInt(500)
    })
    
    processor := NewPaymentProcessor(account)
    result, err := processor.ProcessPayment(req)
    
    require.Error(t, err)
    
    var paymentErr PaymentError
    require.True(t, errors.As(err, &paymentErr))
    assert.Equal(t, "INSUFFICIENT_FUNDS", paymentErr.Code)
    assert.Zero(t, result.ID) // Zero value indicates no payment was created
}

func TestPaymentProcessor_ProcessValidPaymentSuccessfully(t *testing.T) {
    req := NewMockPaymentRequest(func(r *PaymentRequest) {
        r.Amount = decimal.NewFromInt(100)
    })
    
    account := NewMockAccount(func(a *Account) {
        a.Balance = decimal.NewFromInt(500)
    })
    
    processor := NewPaymentProcessor(account)
    result, err := processor.ProcessPayment(req)
    
    require.NoError(t, err)
    assert.NotEmpty(t, result.ID)
    assert.Equal(t, req.Amount, result.Amount)
    assert.Equal(t, PaymentStatusCompleted, result.Status)
}

// Avoid - testing implementation details
func TestPaymentProcessor_CallsCheckBalanceMethod(t *testing.T) {
    // This tests implementation, not behavior - avoid this
}
```

#### Achieving 100% Coverage Through Business Behavior

Example showing how validation code gets 100% coverage without testing it directly:

```go
// payment_validator.go (implementation detail)
func validatePaymentAmount(amount decimal.Decimal) error {
    if amount.LessThanOrEqual(decimal.Zero) {
        return ValidationError{Field: "amount", Message: "must be greater than zero"}
    }
    if amount.GreaterThan(decimal.NewFromInt(10000)) {
        return ValidationError{Field: "amount", Message: "must not exceed £10,000"}
    }
    return nil
}

func validateCardDetails(details PayingCardDetails) error {
    cvvRegex := regexp.MustCompile(`^\d{3,4}$`)
    if !cvvRegex.MatchString(details.CVV) {
        return ValidationError{Field: "cvv", Message: "must be 3 or 4 digits"}
    }
```go
if len(strings.TrimSpace(details.Token)) == 0 {
        return ValidationError{Field: "token", Message: "cannot be empty"}
    }
    return nil
}

// payment_processor.go (public API)
func ProcessPayment(req PaymentRequest) (ProcessedPayment, error) {
    // Validation is used internally but not exposed
    if err := validatePaymentAmount(req.Amount); err != nil {
        return ProcessedPayment{}, PaymentError{
            Code:    "INVALID_AMOUNT",
            Message: "payment amount validation failed",
            Cause:   err,
        }
    }
    
    if err := validateCardDetails(req.CardDetails); err != nil {
        return ProcessedPayment{}, PaymentError{
            Code:    "INVALID_CARD",
            Message: "card details validation failed",
            Cause:   err,
        }
    }
    
    // Process payment...
    return executePayment(req)
}

// payment_processor_test.go
func TestPaymentProcessor_RejectNegativeAmounts(t *testing.T) {
    // These tests achieve 100% coverage of validation code
    // without directly testing the validator functions
    
    req := NewMockPaymentRequest(func(r *PaymentRequest) {
        r.Amount = decimal.NewFromInt(-100)
    })
    
    _, err := ProcessPayment(req)
    
    require.Error(t, err)
    var paymentErr PaymentError
    require.True(t, errors.As(err, &paymentErr))
    assert.Equal(t, "INVALID_AMOUNT", paymentErr.Code)
}

func TestPaymentProcessor_RejectExcessiveAmounts(t *testing.T) {
    req := NewMockPaymentRequest(func(r *PaymentRequest) {
        r.Amount = decimal.NewFromInt(10001)
    })
    
    _, err := ProcessPayment(req)
    
    require.Error(t, err)
    var paymentErr PaymentError
    require.True(t, errors.As(err, &paymentErr))
    assert.Equal(t, "INVALID_AMOUNT", paymentErr.Code)
}

func TestPaymentProcessor_RejectInvalidCVV(t *testing.T) {
    req := NewMockPaymentRequest(func(r *PaymentRequest) {
        r.CardDetails.CVV = "12" // Too short
    })
    
    _, err := ProcessPayment(req)
    
    require.Error(t, err)
    var paymentErr PaymentError
    require.True(t, errors.As(err, &paymentErr))
    assert.Equal(t, "INVALID_CARD", paymentErr.Code)
}

func TestPaymentProcessor_ProcessValidPaymentSuccessfully(t *testing.T) {
    req := NewMockPaymentRequest(func(r *PaymentRequest) {
        r.Amount = decimal.NewFromInt(100)
        r.CardDetails.CVV = "123"
        r.CardDetails.Token = "valid-token"
    })
    
    result, err := ProcessPayment(req)
    
    require.NoError(t, err)
    assert.Equal(t, PaymentStatusCompleted, result.Status)
}
```

### HTTP Handler Testing

```go
// Good - testing HTTP behavior
func TestPaymentHandler_HandleValidPayment(t *testing.T) {
    // Setup
    req := NewMockPaymentRequest()
    reqBody, _ := json.Marshal(req)
    
    httpReq := httptest.NewRequest("POST", "/payments", bytes.NewReader(reqBody))
    httpReq.Header.Set("Content-Type", "application/json")
    
    recorder := httptest.NewRecorder()
    
    // Mock the payment processor
    mockProcessor := &MockPaymentProcessor{}
    mockProcessor.On("ProcessPayment", mock.AnythingOfType("PaymentRequest")).
        Return(ProcessedPayment{
            ID:     "payment_123",
            Status: PaymentStatusCompleted,
            Amount: req.Amount,
        }, nil)
    
    handler := NewPaymentHandler(mockProcessor)
    
    // Execute
    handler.ServeHTTP(recorder, httpReq)
    
    // Assert
    assert.Equal(t, http.StatusCreated, recorder.Code)
    
    var response PaymentResponse
    err := json.Unmarshal(recorder.Body.Bytes(), &response)
    require.NoError(t, err)
    
    assert.Equal(t, "payment_123", response.ID)
    assert.Equal(t, "completed", response.Status)
    
    mockProcessor.AssertExpectations(t)
}

func TestPaymentHandler_HandleInvalidPayment(t *testing.T) {
    invalidReq := `{"amount": -100}` // Invalid JSON structure
    
    httpReq := httptest.NewRequest("POST", "/payments", strings.NewReader(invalidReq))
    httpReq.Header.Set("Content-Type", "application/json")
    
    recorder := httptest.NewRecorder()
    
    mockProcessor := &MockPaymentProcessor{}
    handler := NewPaymentHandler(mockProcessor)
    
    handler.ServeHTTP(recorder, httpReq)
    
    assert.Equal(t, http.StatusBadRequest, recorder.Code)
    
    var response ErrorResponse
    err := json.Unmarshal(recorder.Body.Bytes(), &response)
    require.NoError(t, err)
    
    assert.Contains(t, response.Message, "validation failed")
    
    // Should not call the processor for invalid requests
    mockProcessor.AssertNotCalled(t, "ProcessPayment")
}
```

## Common Patterns to Avoid

### Anti-patterns

```go
// Avoid: Ignoring errors
func ProcessPayment(req PaymentRequest) ProcessedPayment {
    result, _ := executePayment(req) // Don't ignore errors!
    return result
}

// Prefer: Explicit error handling
func ProcessPayment(req PaymentRequest) (ProcessedPayment, error) {
    result, err := executePayment(req)
    if err != nil {
        return ProcessedPayment{}, fmt.Errorf("payment execution failed: %w", err)
    }
    return result, nil
}

// Avoid: Nested conditionals
func ProcessOrder(order Order) error {
    if order.User != nil {
        if order.User.IsActive {
            if order.User.HasPermission("create_order") {
                // do something
            }
        }
    }
    return nil
}

// Prefer: Early returns
func ProcessOrder(order Order) error {
    if order.User == nil {
        return errors.New("user is required")
    }
    
    if !order.User.IsActive {
        return errors.New("user is not active")
    }
    
    if !order.User.HasPermission("create_order") {
        return errors.New("user lacks permission")
    }
    
    // do something
    return nil
}

// Avoid: Large functions
func ProcessCompleteOrder(order Order) error {
    // 100+ lines of code doing everything
}

// Prefer: Composed small functions
func ProcessCompleteOrder(order Order) error {
    if err := validateOrder(order); err != nil {
        return fmt.Errorf("validation failed: %w", err)
    }
    
    if err := calculatePricing(order); err != nil {
        return fmt.Errorf("pricing calculation failed: %w", err)
    }
    
    if err := applyDiscounts(order); err != nil {
        return fmt.Errorf("discount application failed: %w", err)
    }
    
    if err := submitOrder(order); err != nil {
        return fmt.Errorf("order submission failed: %w", err)
    }
    
    return nil
}

// Avoid: Using panic for normal error conditions
func ValidatePayment(req PaymentRequest) {
    if req.Amount.LessThanOrEqual(decimal.Zero) {
        panic("invalid amount") // Don't use panic for business logic!
    }
}

// Prefer: Return errors for recoverable conditions
func ValidatePayment(req PaymentRequest) error {
    if req.Amount.LessThanOrEqual(decimal.Zero) {
        return ValidationError{
            Field:   "amount",
            Message: "must be greater than zero",
        }
    }
    return nil
}
```

### Interface Design Anti-patterns

```go
// Avoid: Interfaces that are too large
type PaymentService interface {
    ProcessPayment(PaymentRequest) (ProcessedPayment, error)
    ValidatePayment(PaymentRequest) error
    CalculateDiscount(PaymentRequest) (decimal.Decimal, error)
    SendNotification(ProcessedPayment) error
    LogPayment(ProcessedPayment) error
    GenerateReceipt(ProcessedPayment) (Receipt, error)
    // ... 10 more methods
}

// Prefer: Small, focused interfaces (Go's "interface segregation")
type PaymentProcessor interface {
    ProcessPayment(ctx context.Context, req PaymentRequest) (ProcessedPayment, error)
}

type PaymentValidator interface {
    ValidatePayment(req PaymentRequest) error
}

type PaymentNotifier interface {
    SendNotification(ctx context.Context, payment ProcessedPayment) error
}

// Compose interfaces when needed
type FullPaymentService interface {
    PaymentProcessor
    PaymentValidator
    PaymentNotifier
}

// Avoid: Premature interface abstraction
type UserRepository interface {
    GetUser(id string) (User, error)
}

type userRepository struct {
    db *sql.DB
}

// If there's only one implementation and no immediate need for testing
// or multiple implementations, start with the concrete type

// Prefer: Start concrete, extract interface when needed
type UserService struct {
    db *sql.DB
}

func (s UserService) GetUser(id string) (User, error) {
    // implementation
}

// Extract interface later when you need it for testing or multiple implementations
```

## Testing Patterns

### Table-Driven Tests

Go's table-driven test pattern is idiomatic and powerful:

```go
func TestValidatePaymentAmount(t *testing.T) {
    tests := []struct {
        name        string
        amount      decimal.Decimal
        expectError bool
        errorMsg    string
    }{
        {
            name:        "valid amount",
            amount:      decimal.NewFromInt(100),
            expectError: false,
        },
        {
            name:        "zero amount",
            amount:      decimal.Zero,
            expectError: true,
            errorMsg:    "must be greater than zero",
        },
        {
            name:        "negative amount",
            amount:      decimal.NewFromInt(-50),
            expectError: true,
            errorMsg:    "must be greater than zero",
        },
        {
            name:        "amount at maximum limit",
            amount:      decimal.NewFromInt(10000),
            expectError: false,
        },
        {
            name:        "amount exceeding maximum",
            amount:      decimal.NewFromInt(10001),
            expectError: true,
            errorMsg:    "must not exceed £10,000",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            req := NewMockPaymentRequest(func(r *PaymentRequest) {
                r.Amount = tt.amount
            })
            
            _, err := ProcessPayment(req)
            
            if tt.expectError {
                require.Error(t, err)
                assert.Contains(t, err.Error(), tt.errorMsg)
            } else {
                require.NoError(t, err)
            }
        })
    }
}
```

### Mocking with Interfaces

```go
// Define interface for dependencies
type PaymentGateway interface {
    ProcessPayment(ctx context.Context, req GatewayRequest) (GatewayResponse, error)
}

// Production implementation
type StripeGateway struct {
    apiKey string
    client *http.Client
}

func (g StripeGateway) ProcessPayment(ctx context.Context, req GatewayRequest) (GatewayResponse, error) {
    // Real Stripe API call
}

// Test implementation
type MockPaymentGateway struct {
    mock.Mock
}

func (m *MockPaymentGateway) ProcessPayment(ctx context.Context, req GatewayRequest) (GatewayResponse, error) {
    args := m.Called(ctx, req)
    return args.Get(0).(GatewayResponse), args.Error(1)
}

// Usage in tests
func TestPaymentService_ProcessPayment(t *testing.T) {
    gateway := &MockPaymentGateway{}
    gateway.On("ProcessPayment", mock.Anything, mock.AnythingOfType("GatewayRequest")).
        Return(GatewayResponse{
            ID:     "gw_123",
            Status: "completed",
        }, nil)
    
    service := NewPaymentService(gateway)
    
    req := NewMockPaymentRequest()
    result, err := service.ProcessPayment(context.Background(), req)
    
    require.NoError(t, err)
    assert.Equal(t, "completed", result.Status)
    
    gateway.AssertExpectations(t)
}
```

## Resources and References

- [Effective Go](https://golang.org/doc/effective_go.html)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- [Go Testing Package](https://golang.org/pkg/testing/)
- [Testify Package](https://github.com/stretchr/testify)
- [Go Project Layout](https://github.com/golang-standards/project-layout)

## Summary

The key is to write clean, testable, idiomatic Go code that evolves through small, safe increments. Every change should be driven by a test that describes the desired behavior, and the implementation should be the simplest thing that makes that test pass. Follow Go's conventions and idioms, handle errors explicitly, and when in doubt, favor simplicity and readability over cleverness.

**Remember**: Test-Driven Development is the foundation that enables all other practices. Without TDD, you cannot have confidence in your refactoring, cannot maintain high-quality code, and cannot evolve your system safely. Every line of production code must be written in response to a failing test.    
