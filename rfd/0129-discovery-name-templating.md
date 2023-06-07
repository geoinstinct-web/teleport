---
authors: Gavin Frazar (gavin.frazar@goteleport.com)
state: draft
---

# RFD 0129 - Avoid Discovery Resource Name Collisions

## Required Approvers

- Engineering: `@r0mant && @smallinsky && @tigrato`
- Product: `@klizhentas || @xinding33`
- Security: `@reedloden || @jentfoo`

## What

Auto-Discovery shall name discovered resources such that other resources of
the same kind are unlikely to have the same name.

In particular, discovered cloud resource names shall include uniquely
identifying metadata in the name such as region, account ID, or sub-type name.

`tsh` sub-commands shall allow users to use a prefix of the resource name when
the prefix unambiguously identifies a resource.

Additionally, `tsh` sub-commands shall support using label selectors to
unambiguously select a single resource.

This RFD does not apply to ssh server instance discovery, since servers are
already identified within the Teleport cluster by a UUID.

## Why

Multiple discovery agents can discover resources with identical names.
For example, this happened when customers had databases in different AWS
regions or accounts with the same name. When a name collision occurs, only one
of the databases can be accessed by users.

Name collisions can be avoided with the addition of other resource metadata
in the resource name.

Since discovered resource names will be longer and more tedious to use, we
should support resource name prefixes and label matching in `tsh` for better UX.

Relevant issue:
- https://github.com/gravitational/teleport/issues/22438

## Details

#### AWS Discovery

Discovered database and kube cluster names shall have a lowercase suffix
appended to it that includes:

- Name of the AWS matcher type
  - `eks`, `rds`, `rdsproxy`, `redshift`, `redshift-serverless`, `elasticache`,
    `memorydb` (as of writing this RFD)
- AWS region
- AWS account ID

All of these AWS resource types require a unique name within an AWS account
and region.

By including the region and account ID, resources of the same kind
in different AWS accounts or regions will avoid name collision with each-other.

By including the Teleport matcher type in the name, resources of different
sub-kinds will also avoid name collision.

By combining these properties, resource names will not collide.

The reason for including `eks` in kube cluster names, even though this is the
only "kind" of kube cluster we discover in AWS, is to clearly distinguish the
cluster further from clusters in other clouds, although this isn't strictly
necessary.

Example:
```yaml
discovery_service:
  enabled: true
  aws:
    - types: ["eks", "rds", "redshift"]
      regions: ["us-west-1", "us-west-2"]
      assume_role_arn: "arn:aws:iam::111111111111:role/DiscoveryRole"
      external_id: "123abc"
      tags:
        "*": "*"
    - types: ["eks", "rds", "redshift"]
      regions: ["us-west-1", "us-west-2"]
      assume_role_arn: "arn:aws:iam::222222222222:role/DiscoveryRole"
      external_id: "456def"
      tags:
        "*": "*"
```

If the discovery service is configured like the above, the discovery agent will
discover AWS EKS clusters and AWS RDS and Redshift databases in the `us-west-1`
and `us-west-2` AWS regions, in AWS accounts `111111111111` and `222222222222`.

Now suppose that an EKS cluster, RDS database, and Redshift database all named
`foo` exist in both regions in both AWS accounts.
If the discovery service applies the new naming convention, the discovered
resources should be named:

- `foo-eks-us-west-1-111111111111`
- `foo-eks-us-west-2-111111111111`
- `foo-eks-us-west-1-222222222222`
- `foo-eks-us-west-2-222222222222`
- `foo-rds-us-west-1-111111111111`
- `foo-rds-us-west-2-111111111111`
- `foo-rds-us-west-1-222222222222`
- `foo-rds-us-west-2-222222222222`
- `foo-redshift-us-west-1-111111111111`
- `foo-redshift-us-west-2-111111111111`
- `foo-redshift-us-west-1-222222222222`
- `foo-redshift-us-west-2-222222222222`

This naming convention does not violate our database name validation regex,
`^[a-z]([-a-z0-9]*[a-z0-9])?$`,
and does not violate our kube cluster name validation regex `^[a-zA-Z0-9._-]+$`.

#### Azure Discovery

Azure resources have a resource ID that uniquely identifies the resource, e.g.:
`/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/<group name>/providers/<provider name>/<name>`

We could use this ID as the database name, but it is unnecessarily verbose.
It will also fail to match our database name validation regex:
`[a-z]([-a-z0-9]*[a-z0-9])?`.

Additionally, all of the Azure databases that Teleport currently supports
require globally unique names (within the same type of database), because Azure
assigns a DNS name:

- Redis: `<name>.redis.cache.windows.net`.
- SQL Server: `<name>.database.windows.net`.
- Postgres: `<name.postgres.database.azure.com`.
- MySQL: `<name>.mysql.database.azure.com`.

MySQL/Postgres server names must be unique among both single-server and
flexible-server instances.

Therefore, we can form a uniquely identifying name among Azure resources just by
adding the kind of matcher to the resource name.
However, AKS kube clusters do not require globally unique names - they only need
to be unique within the same resource group in the same subscription.

To make the naming convention consistent, and to "future-proof" it, the
naming convention will be to append a suffix that includes:

- Name of the Azure matcher type
  - `aks`, `mysql`, `postgres`, `redis`, `sqlserver` (as of writing this RFD)
- Azure resource group name
  - resource group names may contain characters that we do not allow in database
    or kube cluster names.
    The resource group name should be checked for invalid characters and dropped
    from the name suffix if it is invalid.
    This is only a heuristic, but any approach here will be a heuristic, and
    this is the simplest string transform we can do, which avoids confusing
    users with strange resource group names they don't recognize.
- Azure subscription ID
  - subscription IDs only contains letters, digits, and hyphens.

Example:
```yaml
discovery_service:
  enabled: true
  aws:
    - types: ["aks", "mysql", "postgres"]
      regions: ["eastus"]
      subscriptions:
        - "11111111-1111-1111-1111-111111111111"
        - "22222222-2222-2222-2222-222222222222"
      resource_groups: ["group1", "group2", "weird-)(-group-name"]
      tags:
        "*": "*"
```

If the discovery service is configured like the above, the discovery agent will
discover Azure AKS kube clusters, Azure MySQL, and Azure PostgreSQL databases.

Now suppose that four AKS kube clusters named `foo` exist in each combination of
resource group and subscription ID, and a MySQL database and Postgres database
both named `foo` exist in the the `1111..` subscription and `group1`.
If the discovery service applies the new naming convention, the discovered
resources should be named:

- `foo-aks-group1-11111111-1111-1111-1111-111111111111`
- `foo-aks-group2-11111111-1111-1111-1111-111111111111`
- `foo-aks-group1-22222222-2222-2222-2222-222222222222`
- `foo-aks-group2-22222222-2222-2222-2222-222222222222`
- `foo-mysql-group1-11111111-1111-1111-1111-111111111111`
- `foo-postgres-group1-11111111-1111-1111-1111-111111111111`

If resources exist within the Azure resource group `weird-)(-group-name`,
then we simply drop the resource group name from the resource name:

- `foo-aks-11111111-1111-1111-1111-111111111111`
- `foo-aks-22222222-2222-2222-2222-222222222222`
- `foo-mysql-11111111-1111-1111-1111-111111111111`
- ...

Unfortunately, this would allow name collisions across resource groups.

Alternatively, we could apply a transformation to the resource group name to
make it valid.
For example, base64 encode it, make the string lowercase, and replace the
`[+/=]` characters with valid characters, maybe even truncating the result:
(another heuristic, although less likely to collide names):

```sh
$ echo "weird-)(-group-name" | base64 | sed 's#[+/=]#x#g' | tr '[:upper:]' '[:lower:]' | cut -c1-8 
d2vpcmqt
$ echo "other-weird-)(-group-name" | base64 | sed 's#[+/=]#x#g' | tr '[:upper:]' '[:lower:]' | cut -c1-8 
b3rozxit
```

- `foo-aks-d2vpcmqt-11111111-1111-1111-1111-111111111111`
- `foo-aks-b3rozxit-11111111-1111-1111-1111-111111111111`
- ...

Each database name will be unique, since `foo` must be globally unique among
all Azure MySQL databases and globally unique among all Azure Postgres databases.

Even if a new database type is added that doesn't have this globally unique
name property, the resource group name and subscription ID will avoid name
collisions, and the databases will be distinguished from databases in other
clouds.

Likewise, the discovered AKS clusters will avoid colliding with other kube
clusters in Azure or other clouds.

This naming convention does not violate our database name validation regex,
`^[a-z]([-a-z0-9]*[a-z0-9])?$`,
and does not violate our kube cluster name validation regex `^[a-zA-Z0-9._-]+$`.

#### GCP Discovery

GCP discovery currently supports discovering only GKE kube clusters.

GKE cluster names are unique within the same GCP project ID and location/zone.

The discovery naming convention for GKE clusters shall be to append a suffix to
the cluster name that includes:

- Name of the Teleport GCP matcher type
  - `gke`
- GCP project ID
  - These can be custom, but will only consist of characters, digits, hyphens.
- GCP location

```yaml
    gcp:
    - types: ["gke"]
      locations: ["us-west1", "us-west2"]
      tags:
        "*": "*"
      project_ids: ["my-project"]
```

If the discovery service is configured like the above, the discovery agent will
discover GCP GKE kube clusters in "my-project" in the `us-west1` and `us-west2`
locations.

Now suppose GKE clusters named `foo` exist in each region.
If the discovery service applies the new naming convention, the discovered
resources should be named:

- `foo-gke-us-west1-my-project`
- `foo-gke-us-west2-my-project`

This naming convention avoids name collisions between GKE clusters and does not
collide with discovered AWS/Azure clusters.

This naming convention does not violate our kube cluster name validation regex:
`^[a-zA-Z0-9._-]+$`

### `tsh` UX

Users will be frustrated if they are forced to type out verbose resource names
when using `tsh`.
To avoid this poor UX, sub-commands should support prefix resource names or label
matching to identify resources.

The same UX should apply to all `tsh` sub-commands that take a resource name
argument. These commands shall support
`tsh <sub-command> [name | prefix] [key1=value1,key2=value2,...]` syntax:

- `tsh db login`
- `tsh db connect`
- `tsh db env`
- `tsh db config`
- `tsh proxy db`
- `tsh proxy kube`
- `tsh kube login`

#### `tsh` examples

To illustrate the new UX for `tsh` sub-commands, here is an example using
`tsh db connect` to select a database (the same applies for other commands):

```sh
$ tsh db ls
Name   Description         Allowed Users       Labels                      Connect 
------ ------------------- ------------------- --------------------------- ------- 
foo-rds-us-west-1-0123456789012 RDS instance in ... [*] account-id=0123456789012,region=us-west-1,env=prod,...
bar-rds-us-west-1-0123456789012 RDS instance in ... [*] account-id=0123456789012,region=us-west-1,env=dev,...
bar-rds-us-west-2-0123456789012 RDS instance in ... [*] account-id=0123456789012,region=us-west-2,env=dev,...

# connect by prefix name
$ tsh db connect --db-user=alice --db-name-postgres foo
#...connects to "foo-rds-us-west-1-0123456789012" by prefix...

# ambiguous prefix name is an error
$ tsh db connect --db-user=alice --db-name-postgres bar
error: ambiguous database name could match multiple databases:
Name   Description         Allowed Users       Labels                      Connect 
------ ------------------- ------------------- --------------------------- ------- 
bar-rds-us-west-1-0123456789012 RDS instance in ... [*] account-id=0123456789012,region=us-west-1,env=dev,...
bar-rds-us-west-2-0123456789012 RDS instance in ... [*] account-id=0123456789012,region=us-west-2,env=dev,...

Hint: try addressing the database by its full name or by matching its labels.
Hint: use `tsh db ls -v` to list all databases with verbose detail.

# resolve the error by connecting with an unambiguous prefix 
$ tsh db connect --db-user=alice --db-name-postgres bar-rds-us-west-2
#...connects to "bar-rds-us-west-2-0123456789012" by prefix...

# or connect by label(s)
$ tsh db connect --db-user=alice --db-name-postgres region=us-west-2 
#...connects to "bar-rds-us-west-2-0123456789012" by matching region label...

# ambiguous label(s) match is also an error
$ tsh db connect --db-user=alice --db-name-postgres region=us-west-1 
error: ambiguous database labels could match multiple databases:
Name   Description         Allowed Users       Labels                      Connect 
------ ------------------- ------------------- --------------------------- ------- 
foo-rds-us-west-1-0123456789012 RDS instance in ... [*] account-id=0123456789012,region=us-west-1,env=prod,...
bar-rds-us-west-1-0123456789012 RDS instance in ... [*] account-id=0123456789012,region=us-west-1,env=dev,...

# resolve the error by using either more specific labels or adding a prefix name
$ tsh db connect --db-user=alice --db-name-postgres foo region=us-west-1 
#...connects to "foo-rds-us-west-1-0123456789012" by prefix and label...
$ tsh db connect --db-user=alice --db-name-postgres region=us-west-1,env=prod
#...connects to "foo-rds-us-west-1-0123456789012" by multiple labels...
```

### Security

No security concerns I can think of.

### Backward Compatibility

No concerns I can think of.

### Audit Events

N/A

### Test Plan

We should test that discovering multiple resources with identical names does not
suffer name collisions.

Setup identically named RDS databases and kube clusters in different AWS regions
and a discovery agent to discover them.

Check that the resources in each region are discovered and differentiated by
region in their name.

