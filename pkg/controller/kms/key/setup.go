package key

import (
	"context"
	"sort"

	"github.com/aws/aws-sdk-go/aws"
	svcsdk "github.com/aws/aws-sdk-go/service/kms"
	svcsdkapi "github.com/aws/aws-sdk-go/service/kms/kmsiface"
	xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/logging"
	"github.com/crossplane/crossplane-runtime/pkg/meta"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	svcapitypes "github.com/crossplane/provider-aws/apis/kms/v1alpha1"
	"github.com/pkg/errors"
	ctrl "sigs.k8s.io/controller-runtime"
)

// SetupKey adds a controller that reconciles Key.
func SetupKey(mgr ctrl.Manager, l logging.Logger) error {
	name := managed.ControllerName(svcapitypes.KeyGroupKind)
	opts := []option{
		func(e *external) {
			e.preObserve = preObserve
			e.postObserve = postObserve
			e.preCreate = preCreate
			e.postCreate = postCreate
			u := &updater{client: e.client}
			e.update = u.update
			e.delete = delete
			o := &observer{client: e.client}
			e.isUpToDate = o.isUpToDate
			e.lateInitialize = lateInitialize
		},
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		For(&svcapitypes.Key{}).
		Complete(managed.NewReconciler(mgr,
			resource.ManagedKind(svcapitypes.KeyGroupVersionKind),
			managed.WithExternalConnecter(&connector{kube: mgr.GetClient(), opts: opts}),
			managed.WithLogger(l.WithValues("controller", name)),
			managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name)))))
}

func preObserve(_ context.Context, cr *svcapitypes.Key, obj *svcsdk.DescribeKeyInput) error {
	obj.KeyId = aws.String(meta.GetExternalName(cr))
	return nil
}

func postObserve(_ context.Context, cr *svcapitypes.Key, obj *svcsdk.DescribeKeyOutput, obs managed.ExternalObservation, err error) (managed.ExternalObservation, error) {
	if err != nil {
		return obs, err
	}

	// Set Condition
	switch aws.StringValue(obj.KeyMetadata.KeyState) {
	case string(svcapitypes.KeyState_Enabled):
		cr.SetConditions(xpv1.Available())
	case string(svcapitypes.KeyState_Disabled):
		cr.SetConditions(xpv1.Unavailable())
	case string(svcapitypes.KeyState_PendingDeletion):
		cr.SetConditions(xpv1.Deleting())
	case string(svcapitypes.KeyState_PendingImport):
		cr.SetConditions(xpv1.Unavailable())
	case string(svcapitypes.KeyState_Unavailable):
		cr.SetConditions(xpv1.Unavailable())
	}

	return obs, nil
}

func preCreate(_ context.Context, cr *svcapitypes.Key, obj *svcsdk.CreateKeyInput) error {
	return nil
}

func postCreate(_ context.Context, cr *svcapitypes.Key, obj *svcsdk.CreateKeyOutput, creation managed.ExternalCreation, err error) (managed.ExternalCreation, error) {
	if err != nil {
		return creation, err
	}
	meta.SetExternalName(cr, *obj.KeyMetadata.KeyId)

	return managed.ExternalCreation{ExternalNameAssigned: true}, nil
}

type updater struct {
	client svcsdkapi.KMSAPI
}

func (u *updater) update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*svcapitypes.Key)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errUnexpectedObject)
	}

	if _, err := u.client.UpdateKeyDescriptionWithContext(ctx, &svcsdk.UpdateKeyDescriptionInput{
		KeyId:       aws.String(meta.GetExternalName(cr)),
		Description: cr.Spec.ForProvider.Description,
	}); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errUpdate)
	}

	// TODO: policy
	// PutKeyPolicyWithContext(aws.Context, *kms.PutKeyPolicyInput, ...request.Option) (*kms.PutKeyPolicyOutput, error)
	if _, err := u.client.PutKeyPolicyWithContext(ctx, &svcsdk.PutKeyPolicyInput{
		KeyId:      aws.String(meta.GetExternalName(cr)),
		PolicyName: aws.String("default"),
		Policy:     cr.Spec.ForProvider.Policy,
	}); err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errUpdate)
	}

	// TODO: tags
	// UntagResourceWithContext(aws.Context, *kms.UntagResourceInput, ...request.Option) (*kms.UntagResourceOutput, error)
	tagsOutput, err := u.client.ListResourceTagsWithContext(ctx, &svcsdk.ListResourceTagsInput{
		KeyId: aws.String(meta.GetExternalName(cr)),
	})
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errUpdate)
	}
	keepTags, removeTags := diffTags(cr.Spec.ForProvider.Tags, tagsOutput.Tags)
	tags := []*svcsdk.Tag{}
	for _, t := range keepTags {
		tags = append(tags, &svcsdk.Tag{
			TagKey:   t.TagKey,
			TagValue: t.TagValue,
		})
	}
	u.client.TagResourceWithContext(ctx, &svcsdk.TagResourceInput{
		KeyId: aws.String(meta.GetExternalName(cr)),
		Tags:  tags,
	})
	untagKeys := []*string{}
	for _, t := range removeTags {
		untagKeys = append(untagKeys, t.TagKey)
	}
	u.client.UntagResourceWithContext(ctx, &svcsdk.UntagResourceInput{
		KeyId:   aws.String(meta.GetExternalName(cr)),
		TagKeys: untagKeys,
	})

	// TODO: enable/disable
	// TODO: key rotation
	return managed.ExternalUpdate{}, nil
}

// schedule for deletion instead of delete
func delete(ctx context.Context, mg resource.Managed) error {
	cr, ok := mg.(*svcapitypes.Key)
	if !ok {
		return errors.New(errUnexpectedObject)
	}
	_ = aws.String(meta.GetExternalName(cr))

	return nil
}

func lateInitialize(in *svcapitypes.KeyParameters, obj *svcsdk.DescribeKeyOutput) error {
	// TODO: policy
	// GetKeyPolicyWithContext(aws.Context, *kms.GetKeyPolicyInput, ...request.Option) (*kms.GetKeyPolicyOutput, error)

	return nil
}

type observer struct {
	client svcsdkapi.KMSAPI
}

func (o *observer) isUpToDate(cr *svcapitypes.Key, obj *svcsdk.DescribeKeyOutput) bool {
	// TODO: description
	if obj.KeyMetadata.Description != cr.Spec.ForProvider.Description {
		return false
	}

	// Issue: how to do client requests here (possibly returning errors)
	// TODO: policy
	// 	GetKeyPolicyWithContext(aws.Context, *kms.GetKeyPolicyInput, ...request.Option) (*kms.GetKeyPolicyOutput, error)

	// TODO: tags
	// ListResourceTagsWithContext(aws.Context, *kms.ListResourceTagsInput, ...request.Option) (*kms.ListResourceTagsOutput, error)
	return true
}

// returns which AWS Tags exist in the resource tags and which are outdated and should be removed
func diffTags(tags []*svcapitypes.Tag, kmsTags []*svcsdk.Tag) ([]*svcapitypes.Tag, []*svcsdk.Tag) {
	crTags := make(map[string]*svcapitypes.Tag)
	for _, t := range tags {
		crTags[*t.TagKey] = t
	}

	existing := []*svcapitypes.Tag{}
	outdated := []*svcsdk.Tag{}
	for _, kmsTag := range kmsTags {
		if crTag, isPresent := crTags[*kmsTag.TagKey]; isPresent {
			existing = append(existing, crTag)
		} else {
			outdated = append(outdated, kmsTag)
		}
	}
	return existing, outdated
}

func compareTags(tags []svcapitypes.Tag, kmsTags []svcsdk.Tag) bool {
	if len(tags) != len(kmsTags) {
		return false
	}

	sortTags(tags, kmsTags)

	for i, t := range tags {
		if *t.TagKey != *kmsTags[i].TagKey || *t.TagValue != *kmsTags[i].TagValue {
			return false
		}
	}

	return true
}

// sortTags sorts array of svcapitypes.Tag and kms.Tag on 'Key'
func sortTags(tags []svcapitypes.Tag, kmsTags []svcsdk.Tag) {
	sort.Slice(tags, func(i, j int) bool {
		return *tags[i].TagKey < *tags[j].TagKey
	})

	sort.Slice(kmsTags, func(i, j int) bool {
		return *kmsTags[i].TagKey < *kmsTags[j].TagKey
	})
}
