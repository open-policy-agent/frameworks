package client

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/errors"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/handler/handlertest"
)

func TestConstraintMatchers_Add(t *testing.T) {
	tests := []struct {
		name    string
		before  *constraintMatchers
		key     matcherKey
		matcher constraints.Matcher
		want    *constraintMatchers
	}{
		{
			name:    "add to empty",
			before:  &constraintMatchers{},
			key:     matcherKey{target: "foo", kind: "bar", name: "qux"},
			matcher: handlertest.Matcher{},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
		},
		{
			name: "overwrite with identical",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
			key:     matcherKey{target: "foo", kind: "bar", name: "qux"},
			matcher: handlertest.Matcher{},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
		},
		{
			name: "overwrite with new",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{Namespace: "aaa"},
						},
					},
				},
			},
			key:     matcherKey{target: "foo", kind: "bar", name: "qux"},
			matcher: handlertest.Matcher{Namespace: "bbb"},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{Namespace: "bbb"},
						},
					},
				},
			},
		},
		{
			name: "add with different name",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{Namespace: "aaa"},
						},
					},
				},
			},
			key:     matcherKey{target: "foo", kind: "bar", name: "cog"},
			matcher: handlertest.Matcher{Namespace: "bbb"},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{Namespace: "aaa"},
							"cog": handlertest.Matcher{Namespace: "bbb"},
						},
					},
				},
			},
		},
		{
			name: "add with different kind",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{Namespace: "aaa"},
						},
					},
				},
			},
			key:     matcherKey{target: "foo", kind: "cog", name: "qux"},
			matcher: handlertest.Matcher{Namespace: "bbb"},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{Namespace: "aaa"},
						},
						"cog": {
							"qux": handlertest.Matcher{Namespace: "bbb"},
						},
					},
				},
			},
		},
		{
			name: "add with different target",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{Namespace: "aaa"},
						},
					},
				},
			},
			key:     matcherKey{target: "cog", kind: "bar", name: "qux"},
			matcher: handlertest.Matcher{Namespace: "bbb"},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{Namespace: "aaa"},
						},
					},
					"cog": {
						"bar": {
							"qux": handlertest.Matcher{Namespace: "bbb"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.before

			got.Add(tt.key, tt.matcher)

			if diff := cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(constraintMatchers{})); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestConstraintMatchers_Remove(t *testing.T) {
	tests := []struct {
		name   string
		before *constraintMatchers
		key    matcherKey
		want   *constraintMatchers
	}{
		{
			name:   "remove from empty",
			before: &constraintMatchers{},
			key:    matcherKey{target: "foo", kind: "bar", name: "qux"},
			want:   &constraintMatchers{},
		},
		{
			name: "remove from empty target",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {},
				},
			},
			key: matcherKey{target: "foo", kind: "bar", name: "qux"},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {},
				},
			},
		},
		{
			name: "remove from empty kind",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {},
					},
				},
			},
			key: matcherKey{target: "foo", kind: "bar", name: "qux"},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {},
					},
				},
			},
		},
		{
			name: "remove last from target",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
			key: matcherKey{target: "foo", kind: "bar", name: "qux"},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{},
			},
		},
		{
			name: "remove last from kind",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
						"cog": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
			key: matcherKey{target: "foo", kind: "bar", name: "qux"},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"cog": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
		},
		{
			name: "remove",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
							"cog": handlertest.Matcher{},
						},
					},
				},
			},
			key: matcherKey{target: "foo", kind: "bar", name: "qux"},
			want: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"cog": handlertest.Matcher{},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.before

			got.Remove(tt.key)

			if diff := cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(constraintMatchers{})); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestConstraintMatchers_RemoveAll(t *testing.T) {
	tests := []struct {
		name   string
		before *constraintMatchers
		kind   string
		want   *constraintMatchers
	}{
		{
			name:   "remove from empty",
			before: &constraintMatchers{},
			kind:   "bar",
			want:   &constraintMatchers{},
		},
		{
			name: "remove from empty handler",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {},
				},
			},
			kind: "bar",
			want: &constraintMatchers{},
		},
		{
			name: "remove last from handler",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
			kind: "bar",
			want: &constraintMatchers{},
		},
		{
			name: "remove from handler",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
						"cog": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
			kind: "bar",
			want: &constraintMatchers{},
		},
		{
			name: "remove from multiple handlers",
			before: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
					},
					"cog": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
			kind: "bar",
			want: &constraintMatchers{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.before

			got.RemoveAll(tt.kind)

			if diff := cmp.Diff(tt.want, got, cmpopts.IgnoreUnexported(constraintMatchers{})); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestConstraintMatchers_ConstraintsFor(t *testing.T) {
	tests := []struct {
		name     string
		matchers *constraintMatchers
		review   interface{}
		want     map[string]map[string][]string
		wantErrs error
	}{
		{
			name:     "no matchers",
			matchers: &constraintMatchers{},
			review: &handlertest.Review{
				Object: handlertest.Object{Namespace: "aaa"},
			},
			want:     map[string]map[string][]string{},
			wantErrs: nil,
		},
		{
			name: "match one",
			matchers: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
			review: &handlertest.Review{
				Object: handlertest.Object{Namespace: "aaa"},
			},
			want: map[string]map[string][]string{
				"foo": {
					"bar": []string{"qux"},
				},
			},
			wantErrs: nil,
		},
		{
			name: "match two same kind",
			matchers: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
							"cog": handlertest.Matcher{},
						},
					},
				},
			},
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: map[string]map[string][]string{
				"foo": {
					"bar": []string{"cog", "qux"},
				},
			},
			wantErrs: nil,
		},
		{
			name: "match two different kinds",
			matchers: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
						"cog": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: map[string]map[string][]string{
				"foo": {
					"bar": []string{"qux"},
					"cog": []string{"qux"},
				},
			},
			wantErrs: nil,
		},
		{
			name: "match two different targets",
			matchers: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
					},
					"cog": {
						"bar": {
							"qux": handlertest.Matcher{},
						},
					},
				},
			},
			review: &handlertest.Review{
				Object: handlertest.Object{},
			},
			want: map[string]map[string][]string{
				"foo": {
					"bar": []string{"qux"},
				},
				"cog": {
					"bar": []string{"qux"},
				},
			},
			wantErrs: nil,
		},
		{
			name: "match one but not the other",
			matchers: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{
								Namespace: "aaa",
							},
							"cog": handlertest.Matcher{
								Namespace: "bbb",
							},
						},
					},
				},
			},
			review: &handlertest.Review{
				Object: handlertest.Object{Namespace: "aaa"},
			},
			want: map[string]map[string][]string{
				"foo": {
					"bar": []string{"qux"},
				},
			},
			wantErrs: nil,
		},
		{
			name: "error matching",
			matchers: &constraintMatchers{
				matchers: map[string]map[string]map[string]constraints.Matcher{
					"foo": {
						"bar": {
							"qux": handlertest.Matcher{
								Namespace: "aaa",
							},
						},
					},
				},
			},
			review: "nope",
			want:   nil,
			wantErrs: &errors.ErrorMap{
				"foo bar qux": handlertest.ErrInvalidType,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.matchers.ConstraintsFor(tt.review)
			if diff := cmp.Diff(tt.wantErrs, err, cmpopts.EquateErrors()); diff != "" {
				t.Fatal(diff)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Error(diff)
			}
		})
	}
}
