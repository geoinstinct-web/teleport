---
authors: Michael Myers (michael.myers@goteleport.com)
state: draft
---

# RFD 0148 - Pinned Unified Resources in the web UI

## Required approvers

TODO

## What

This RFD discusses the method of "pinning" resources in the web UI. Pinning will allow users to have 
specific resources in a tab that they want to have easier access to. Pinning is analogous to "favoriting"

![unnamed](https://github.com/gravitational/teleport/assets/5201977/affe68b9-323f-4aa0-948c-9d8fb53f8c01)
![unnamed-1](https://github.com/gravitational/teleport/assets/5201977/1f9c5915-4cde-478c-b788-cd49b04edcd3)




## Why

Generally, most users access some resources much more than others. We reduced friction of search/discovery by
adding in the unified resource view. Pinning takes this view one step further by allowing them to keep their
favorite resources always within a click or two away without needing to search and filter for the same resource
every day. 

## Details

### User Preferences

Pinned resources will be stored on the `UserPrefernces` object `ClusterPreferences`, which has an array of resource IDs `pinnedResources` (that match the id used in our unified resources caches, ex: `theservername/node`, `grafana/app`, etc). 


```diff

+type ClusterPreferences struct {
+	PinnedResources []string `json:"pinnedResources"`
+}

type UserPreferencesResponse struct {
	Assist AssistUserPreferencesResponse `json:"assist"`
	Theme userpreferencesv1.Theme `json:"theme"`
	Onboard OnboardUserPreferencesResponse `json:"onboard"`
+	ClusterPreferences ClusterPreferences `json:"clusterPreferences"`
}
```

Defined in protobuf as below:
```protobuf
// PinnedResourcesUserPreferences is a collection of resource IDs that will be
// displayed in the user's pinned resources tab in the Web UI
message PinnedResourcesUserPreferences {
  // pinned_resources is a map of resource IDs
  repeated string resource_ids = 1;
}

// ClusterUserPreferences are user preferences saved per cluster
message ClusterUserPreferences {
  PinnedResourcesUserPreferences pinned_resources = 1;
}

message UserPreferences {
  // assist is the preferences for the Teleport Assist.
  v1.AssistUserPreferences assist = 1;
  // theme is the theme of the frontend.
  Theme theme = 2;
  // onboard is the preferences from the onboarding questionnaire.
  v1.OnboardUserPreferences onboard = 3;
  // cluster_preferences are user preferences saved per cluster
  v1.ClusterUserPreferences cluster_preferences = 4;
}
```

Currently, user preferences are only access via the root auth server. This makes sense for things like theme where
it is expected that the user would want the same theme across all clusters. However, with pinned resources,
we would want a separate list per cluster. Instead of creating a new mechanism to store pinned resources, we can
reuse the current user preferences method but update/fetch pinned resources per cluster instead. We can update the current
get/put endpoints for userpreferences to have an optional param `clusterPreferences` to determine which auth client to use 
between root and leaf. 

#### Filtering Pinned Resources

The current implementation of unified resources will pull the entire set of unified resources from the unified resource cache (we will call this the "to-be-filtered" list) and then filter down based on the provider params. You can think of Pinned Resources as just another filter, but instead of pulling everything into the "to-be-filtered" list, we only populate the "to-be-filtered" list with resources that match the provided resource IDs.

```go
func (c *UnifiedResourceCache) GetUnifiedResourcesByIDs(ctx context.Context, ids []string) ([]types.ResourceWithLabels, error) {
	var resources []types.ResourceWithLabels

	err := c.read(ctx, func(tree *btree.BTreeG[*item]) error {
		for _, id := range ids {
			res, found := tree.Get(&item{Key: backend.Key(prefix, id)})
			if found {
				resources = append(resources, res.Value.CloneResource())
			}
		}
		return nil
	})
	if err != nil {
		return nil, trace.Wrap(err, "getting unified resources by id")
	}

	return resources, nil
}
```
After this, any existing filters in the request will be applied the same (including RBAC).  

### Space limitations for UserPreferences storage
> The maximum item size in DynamoDB is **400 KB**, which includes both attribute name binary length (UTF-8 length) and attribute value lengths (again binary length). The attribute name counts towards the size limit.

If we assume an average resource ID is something like `db-name-1aaa8584-0e54-4c89-bec9-34f957512078`, then we can
store well above 10,000 pinned resources per user. This is a very unlikely scenario as any amount of pinned resources over 20, 
lets just say for conversation sake, defeats the purpose of pinning a resource in the first place. We don't expect anyone to pin 
more than a "page" worth. We can still limit the resources in the backend to a total (per cluster) of something like 500. 
These are knobs we can easily turn if necessary but it seems unlikely to "deliberately" go over this cap.

### "What happens if a resource I have pinned becomes unavailable?"
Similarly to the normal resource view, if a resource becomes unavailable (due to RBAC or being removed) it just won't be visible in the pinned view either. 

### Manual Cleanup
As of now, there would be no way to manually clean up a pinned resource that isn't available because the UI would never show the tile. We could perhaps decide to show a list of tiles that aren't available but without knowing the "why" (is it gone? connectivity? rbac?) it may be more confusing to see a tile unavailable with no other info, other than the ID, than it would to just have it not shown. An example of that would be like so

![Untitled-2022-09-11-1530](https://github.com/gravitational/teleport/assets/5201977/e52c4286-bf57-49cc-bfb5-d541146f6896)

If a resource isn't found for whatever reason when fetching, we can display it's name (name/type or hostname/type) in a "disconnected" state. This will allow the user to make the decision themselves to unpin something. Without the resource information the displayable card would only have it's name/type but that should be sufficient enough to know "what" is disconnected. 

### Security Concerns
Pinned resources go through the same RBAC as unified resources so no additional security concerns matter in the listing. 

### Backward compatibility
If the user tries to access a cluster that doesn't have access to pinned resources, we can hide the feature and show 
the normal unified resource view without pinning capability (the same as v14.0 view). This mechanism will be similar
to the one used to check if unified resources is enabled by making a fetch to see if the endpoint exists. This can be
done per cluster as well since we will be fetching each time the cluster is changed.
