package handlertest

// Review is the request to review Object.
type Review struct {
	Object Object `json:"object"`
}

func NewReview(namespace, name, data string) *Review {
	return &Review{Object: Object{
		Name:      name,
		Namespace: namespace,
		Data:      data,
	}}
}
