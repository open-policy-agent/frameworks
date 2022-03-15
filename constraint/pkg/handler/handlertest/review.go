package handlertest

// Review is the request to review Object.
type Review struct {
	Ignored bool   `json:"ignored"`
	Object  Object `json:"object"`
}

func NewReview(namespace, name, data string) *Review {
	return &Review{Object: Object{
		Name:      name,
		Namespace: namespace,
		Data:      data,
	}}
}
