package kms

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/google/go-cmp/cmp"

	"github.com/crossplane/provider-aws/apis/kms/v1alpha1"
)

var (
	cidr             = "192.18.0.0/32"
	vpc              = "some vpc"
	availableIPCount = 10
	subnetID         = "some subnet"
	state            = "available"

	params = v1alpha1.KeyParameters{}
	tags   = []v1alpha1.Tag{
		{
			Key:   "a",
			Value: "b",
		},
	}
)

func TestIsUpToDate(t *testing.T) {
	type args struct {
		spec   *v1alpha1.KeyParameters
		policy *string
		tags   []kms.Tag
	}

	cases := map[string]struct {
		args args
		want bool
	}{
		"SameFields": {
			args: args{
				spec: &v1alpha1.KeyParameters{
					Region:     "eu-central",
					JSONPolicy: aws.String("{}"),
					Tags:       tags,
				},
				policy: aws.String("{}"),
				tags: []kms.Tag{
					{
						TagKey:   aws.String(tags[0].Key),
						TagValue: aws.String(tags[0].Value),
					},
				},
			},
			want: true,
		},
		"Missing Tags": {
			args: args{
				spec: &v1alpha1.KeyParameters{
					Region:     "eu-central",
					JSONPolicy: aws.String("{}"),
					Tags:       tags,
				},
				policy: aws.String("{}"),
				tags:   []kms.Tag{},
			},
			want: false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := IsUpToDate(tc.args.spec, tc.args.policy, tc.args.tags)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("r: -want, +got:\n%s", diff)
			}
		})
	}
}
