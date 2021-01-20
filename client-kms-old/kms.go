package kms

import (
	"sort"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/awserr"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/crossplane/provider-aws/apis/kms/v1alpha1"
	awsclients "github.com/crossplane/provider-aws/pkg/clients"
)

const (
	// VPCIDNotFound is the code that is returned by ec2 when the given VPCID is not valid
	VPCIDNotFound = "InvalidVpcID.NotFound"
)

// Client is the external client used for KMS Custom Resource
type Client interface {
	CreateKeyRequest(*kms.CreateKeyInput) kms.CreateKeyRequest
	ScheduleKeyDeletionRequest(*kms.ScheduleKeyDeletionInput) kms.ScheduleKeyDeletionRequest
	DescribeKeyRequest(*kms.DescribeKeyInput) kms.DescribeKeyRequest
	ListKeysRequest(*kms.ListKeysInput) kms.ListKeysRequest
	TagResourceRequest(*kms.TagResourceInput) kms.TagResourceRequest
	ListResourceTagsRequest(*kms.ListResourceTagsInput) kms.ListResourceTagsRequest
	GetKeyPolicyRequest(*kms.GetKeyPolicyInput) kms.GetKeyPolicyRequest
	PutKeyPolicyRequest(*kms.PutKeyPolicyInput) kms.PutKeyPolicyRequest
}

// NewClient returns a new client using AWS credentials as JSON encoded data.
func NewClient(cfg aws.Config) Client {
	return kms.New(cfg)
}

// IsErrorNotFound return true if the error is because the item doesn't exist
func IsErrorNotFound(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		if awsErr.Code() == kms.ErrCodeNotFoundException {
			return true
		}
	}

	return false
}

// GenerateObservation is used to produce v1beta1.VPCObservation from
// ec2.Vpc.
func GenerateObservation(metadata *kms.KeyMetadata) v1alpha1.KeyObservation {
	o := v1alpha1.KeyObservation{
		KeyArn:   awsclients.StringValue(metadata.Arn),
		KeyID:    awsclients.StringValue(metadata.KeyId),
		KeyState: metadata.KeyState,
	}

	if metadata.CreationDate != nil {
		o.CreatedAt = &metav1.Time{Time: *metadata.CreationDate}
	}

	return o
}

// IsUpToDate returns true if there is no update-able difference between desired and observed state of the resource
func IsUpToDate(spec *v1alpha1.KeyParameters, policy *string, tags []kms.Tag) bool {
	if *spec.JSONPolicy != *policy {
		return false
	}
	return compareTags(spec.Tags, tags)
}

// LateInitialize fills the empty fields in *v1alpha1.KeyParameters with the values seen in kms.Key
func LateInitialize(in *v1alpha1.KeyParameters, key *kms.KeyMetadata, policy *string, tags []kms.Tag) {
	if key == nil {
		return
	}

	if len(*in.JSONPolicy) == 0 && len(*policy) != 0 {
		in.JSONPolicy = policy
	}

	if in.Tags == nil && tags != nil {
		in.Tags = BuildFromKMSTags(tags)
	}
}

// BuildFromKMSTags converts AWS KMS Tags to tag array
func BuildFromKMSTags(tags []kms.Tag) []v1alpha1.Tag {
	if len(tags) < 1 {
		return nil
	}
	res := make([]v1alpha1.Tag, len(tags))
	for i, t := range tags {
		res[i] = v1alpha1.Tag{
			Key:   aws.StringValue(t.TagKey),
			Value: aws.StringValue(t.TagValue),
		}
	}

	return res
}

// GenerateKMSTags generates a tag array with type that KMS client expects.
func GenerateKMSTags(tags []v1alpha1.Tag) []kms.Tag {
	res := make([]kms.Tag, len(tags))
	for i, t := range tags {
		res[i] = kms.Tag{TagKey: aws.String(t.Key), TagValue: aws.String(t.Value)}
	}
	return res
}

// compareTags compares arrays of v1alpha1.Tag and kms.Tag
func compareTags(tags []v1alpha1.Tag, kmsTags []kms.Tag) bool {
	if len(tags) != len(kmsTags) {
		return false
	}

	sortTags(tags, kmsTags)

	for i, t := range tags {
		if t.Key != *kmsTags[i].TagKey || t.Value != *kmsTags[i].TagValue {
			return false
		}
	}

	return true
}

// sortTags sorts array of v1alpha1.Tag and kms.Tag on 'Key'
func sortTags(tags []v1alpha1.Tag, kmsTags []kms.Tag) {
	sort.Slice(tags, func(i, j int) bool {
		return tags[i].Key < tags[j].Key
	})

	sort.Slice(kmsTags, func(i, j int) bool {
		return *kmsTags[i].TagKey < *kmsTags[j].TagKey
	})
}
