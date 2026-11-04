package client

// The fixed lists of text values of the API. Use these names instead of writing the text by hand.
// A newer API can send a value that this library does not know yet: Valid says whether it knows one.

// valid says whether the value is one of the known values of its list.
func valid[T comparable](value T, known []T) bool {
	for _, k := range known {
		if value == k {
			return true
		}
	}
	return false
}

// Purpose is what a session is for.
type Purpose string

const (
	PurposeEnrol            Purpose = "enrol"
	PurposeEntry            Purpose = "entry"
	PurposeView             Purpose = "view"
	PurposeApprove          Purpose = "approve"
	PurposeRecover          Purpose = "recover"
	PurposeRecoverySettings Purpose = "recovery_settings"
	PurposeReset            Purpose = "reset"
	PurposeDelete           Purpose = "delete"
	PurposeHolder           Purpose = "holder"
)

// Purposes lists every purpose a business can start.
func Purposes() []Purpose {
	return []Purpose{
		PurposeEnrol, PurposeEntry, PurposeView, PurposeApprove, PurposeRecover,
		PurposeRecoverySettings, PurposeReset, PurposeDelete, PurposeHolder,
	}
}

func (p Purpose) Valid() bool { return valid(p, Purposes()) }

// SessionStatus is where a session is in its life.
type SessionStatus string

const (
	SessionCreated   SessionStatus = "created"
	SessionExchanged SessionStatus = "exchanged"
	SessionCompleted SessionStatus = "completed"
	SessionCancelled SessionStatus = "cancelled"
	SessionExpired   SessionStatus = "expired"
)

func SessionStatuses() []SessionStatus {
	return []SessionStatus{SessionCreated, SessionExchanged, SessionCompleted, SessionCancelled, SessionExpired}
}

func (s SessionStatus) Valid() bool { return valid(s, SessionStatuses()) }

// DisclosureStatus is where a disclosure request is in its life.
type DisclosureStatus string

const (
	DisclosurePending   DisclosureStatus = "pending"
	DisclosureApproved  DisclosureStatus = "approved"
	DisclosureRejected  DisclosureStatus = "rejected"
	DisclosureCancelled DisclosureStatus = "cancelled"
	DisclosureExpired   DisclosureStatus = "expired"
)

func DisclosureStatuses() []DisclosureStatus {
	return []DisclosureStatus{DisclosurePending, DisclosureApproved, DisclosureRejected, DisclosureCancelled, DisclosureExpired}
}

func (s DisclosureStatus) Valid() bool { return valid(s, DisclosureStatuses()) }

// DisclosureKeyStatus says whether a disclosure key is in use, being replaced, or no longer used.
type DisclosureKeyStatus string

const (
	DisclosureKeyActive   DisclosureKeyStatus = "active"
	DisclosureKeyRetiring DisclosureKeyStatus = "retiring"
	DisclosureKeyRetired  DisclosureKeyStatus = "retired"
)

func DisclosureKeyStatuses() []DisclosureKeyStatus {
	return []DisclosureKeyStatus{DisclosureKeyActive, DisclosureKeyRetiring, DisclosureKeyRetired}
}

func (s DisclosureKeyStatus) Valid() bool { return valid(s, DisclosureKeyStatuses()) }

// WebhookEndpointStatus says whether a webhook endpoint receives events.
type WebhookEndpointStatus string

const (
	WebhookEndpointEnabled  WebhookEndpointStatus = "enabled"
	WebhookEndpointDisabled WebhookEndpointStatus = "disabled"
)

func WebhookEndpointStatuses() []WebhookEndpointStatus {
	return []WebhookEndpointStatus{WebhookEndpointEnabled, WebhookEndpointDisabled}
}

func (s WebhookEndpointStatus) Valid() bool { return valid(s, WebhookEndpointStatuses()) }

// WebhookDeliveryStatus is where one webhook delivery is.
type WebhookDeliveryStatus string

const (
	WebhookDeliveryPending   WebhookDeliveryStatus = "pending"
	WebhookDeliveryRetrying  WebhookDeliveryStatus = "retrying"
	WebhookDeliveryDelivered WebhookDeliveryStatus = "delivered"
	WebhookDeliveryFailed    WebhookDeliveryStatus = "failed"
)

func WebhookDeliveryStatuses() []WebhookDeliveryStatus {
	return []WebhookDeliveryStatus{WebhookDeliveryPending, WebhookDeliveryRetrying, WebhookDeliveryDelivered, WebhookDeliveryFailed}
}

func (s WebhookDeliveryStatus) Valid() bool { return valid(s, WebhookDeliveryStatuses()) }

// CustomerState says whether a customer can use their vault, or must enrol again after a reset.
type CustomerState string

const (
	CustomerActive               CustomerState = "active"
	CustomerResetEnrolmentNeeded CustomerState = "reset: enrolment needed"
)

func CustomerStates() []CustomerState {
	return []CustomerState{CustomerActive, CustomerResetEnrolmentNeeded}
}

func (s CustomerState) Valid() bool { return valid(s, CustomerStates()) }
