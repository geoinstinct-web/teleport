// Code generated by github.com/Khan/genqlient, DO NOT EDIT.

package main

import (
	"context"
	"time"

	"github.com/Khan/genqlient/graphql"
)

// The possible states for a check suite or run conclusion.
type CheckConclusionState string

const (
	// The check suite or run requires action.
	CheckConclusionStateActionRequired CheckConclusionState = "ACTION_REQUIRED"
	// The check suite or run has been cancelled.
	CheckConclusionStateCancelled CheckConclusionState = "CANCELLED"
	// The check suite or run has failed.
	CheckConclusionStateFailure CheckConclusionState = "FAILURE"
	// The check suite or run was neutral.
	CheckConclusionStateNeutral CheckConclusionState = "NEUTRAL"
	// The check suite or run was skipped.
	CheckConclusionStateSkipped CheckConclusionState = "SKIPPED"
	// The check suite or run was marked stale by GitHub. Only GitHub can use this conclusion.
	CheckConclusionStateStale CheckConclusionState = "STALE"
	// The check suite or run has failed at startup.
	CheckConclusionStateStartupFailure CheckConclusionState = "STARTUP_FAILURE"
	// The check suite or run has succeeded.
	CheckConclusionStateSuccess CheckConclusionState = "SUCCESS"
	// The check suite or run has timed out.
	CheckConclusionStateTimedOut CheckConclusionState = "TIMED_OUT"
)

// __getLatestPRsInput is used internally by genqlient
type __getLatestPRsInput struct {
	Owner  string  `json:"owner"`
	Repo   string  `json:"repo"`
	Limit  int     `json:"limit"`
	Before *string `json:"before"`
}

// GetOwner returns __getLatestPRsInput.Owner, and is useful for accessing the field via an interface.
func (v *__getLatestPRsInput) GetOwner() string { return v.Owner }

// GetRepo returns __getLatestPRsInput.Repo, and is useful for accessing the field via an interface.
func (v *__getLatestPRsInput) GetRepo() string { return v.Repo }

// GetLimit returns __getLatestPRsInput.Limit, and is useful for accessing the field via an interface.
func (v *__getLatestPRsInput) GetLimit() int { return v.Limit }

// GetBefore returns __getLatestPRsInput.Before, and is useful for accessing the field via an interface.
func (v *__getLatestPRsInput) GetBefore() *string { return v.Before }

// getLatestPRsRepository includes the requested fields of the GraphQL type Repository.
// The GraphQL type's documentation follows.
//
// A repository contains the content for a project.
type getLatestPRsRepository struct {
	// A list of pull requests that have been opened in the repository.
	PullRequests getLatestPRsRepositoryPullRequestsPullRequestConnection `json:"pullRequests"`
}

// GetPullRequests returns getLatestPRsRepository.PullRequests, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepository) GetPullRequests() getLatestPRsRepositoryPullRequestsPullRequestConnection {
	return v.PullRequests
}

// getLatestPRsRepositoryPullRequestsPullRequestConnection includes the requested fields of the GraphQL type PullRequestConnection.
// The GraphQL type's documentation follows.
//
// The connection type for PullRequest.
type getLatestPRsRepositoryPullRequestsPullRequestConnection struct {
	// Information to aid in pagination.
	PageInfo getLatestPRsRepositoryPullRequestsPullRequestConnectionPageInfo `json:"pageInfo"`
	// A list of nodes.
	Nodes []*getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequest `json:"nodes"`
}

// GetPageInfo returns getLatestPRsRepositoryPullRequestsPullRequestConnection.PageInfo, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnection) GetPageInfo() getLatestPRsRepositoryPullRequestsPullRequestConnectionPageInfo {
	return v.PageInfo
}

// GetNodes returns getLatestPRsRepositoryPullRequestsPullRequestConnection.Nodes, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnection) GetNodes() []*getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequest {
	return v.Nodes
}

// getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequest includes the requested fields of the GraphQL type PullRequest.
// The GraphQL type's documentation follows.
//
// A repository pull request.
type getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequest struct {
	// Identifies the pull request number.
	Number int `json:"number"`
	// The date and time that the pull request was merged.
	MergedAt *time.Time `json:"mergedAt"`
	// A list of commits present in this pull request's head branch not present in the base branch.
	Commits getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnection `json:"commits"`
}

// GetNumber returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequest.Number, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequest) GetNumber() int {
	return v.Number
}

// GetMergedAt returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequest.MergedAt, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequest) GetMergedAt() *time.Time {
	return v.MergedAt
}

// GetCommits returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequest.Commits, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequest) GetCommits() getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnection {
	return v.Commits
}

// getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnection includes the requested fields of the GraphQL type PullRequestCommitConnection.
// The GraphQL type's documentation follows.
//
// The connection type for PullRequestCommit.
type getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnection struct {
	// A list of nodes.
	Nodes []*getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommit `json:"nodes"`
}

// GetNodes returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnection.Nodes, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnection) GetNodes() []*getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommit {
	return v.Nodes
}

// getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommit includes the requested fields of the GraphQL type PullRequestCommit.
// The GraphQL type's documentation follows.
//
// Represents a Git commit part of a pull request.
type getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommit struct {
	// The Git commit object
	Commit getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommit `json:"commit"`
}

// GetCommit returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommit.Commit, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommit) GetCommit() getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommit {
	return v.Commit
}

// getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommit includes the requested fields of the GraphQL type Commit.
// The GraphQL type's documentation follows.
//
// Represents a Git commit.
type getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommit struct {
	// The check suites associated with a commit.
	CheckSuites *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnection `json:"checkSuites"`
}

// GetCheckSuites returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommit.CheckSuites, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommit) GetCheckSuites() *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnection {
	return v.CheckSuites
}

// getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnection includes the requested fields of the GraphQL type CheckSuiteConnection.
// The GraphQL type's documentation follows.
//
// The connection type for CheckSuite.
type getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnection struct {
	// A list of nodes.
	Nodes []*getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuite `json:"nodes"`
}

// GetNodes returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnection.Nodes, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnection) GetNodes() []*getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuite {
	return v.Nodes
}

// getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuite includes the requested fields of the GraphQL type CheckSuite.
// The GraphQL type's documentation follows.
//
// A check suite.
type getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuite struct {
	// The GitHub App which created this check suite.
	App *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteApp `json:"app"`
	// The check runs associated with a check suite.
	CheckRuns *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnection `json:"checkRuns"`
}

// GetApp returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuite.App, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuite) GetApp() *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteApp {
	return v.App
}

// GetCheckRuns returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuite.CheckRuns, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuite) GetCheckRuns() *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnection {
	return v.CheckRuns
}

// getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteApp includes the requested fields of the GraphQL type App.
// The GraphQL type's documentation follows.
//
// A GitHub App.
type getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteApp struct {
	// The name of the app.
	Name string `json:"name"`
}

// GetName returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteApp.Name, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteApp) GetName() string {
	return v.Name
}

// getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnection includes the requested fields of the GraphQL type CheckRunConnection.
// The GraphQL type's documentation follows.
//
// The connection type for CheckRun.
type getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnection struct {
	// A list of nodes.
	Nodes []*getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun `json:"nodes"`
}

// GetNodes returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnection.Nodes, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnection) GetNodes() []*getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun {
	return v.Nodes
}

// getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun includes the requested fields of the GraphQL type CheckRun.
// The GraphQL type's documentation follows.
//
// A check run.
type getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun struct {
	// The name of the check for this check run.
	Name string `json:"name"`
	// The conclusion of the check run.
	Conclusion *CheckConclusionState `json:"conclusion"`
	// Identifies the date and time when the check run was started.
	StartedAt *time.Time `json:"startedAt"`
	// Identifies the date and time when the check run was completed.
	CompletedAt *time.Time `json:"completedAt"`
	// The permalink to the check run summary.
	Permalink string `json:"permalink"`
}

// GetName returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun.Name, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun) GetName() string {
	return v.Name
}

// GetConclusion returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun.Conclusion, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun) GetConclusion() *CheckConclusionState {
	return v.Conclusion
}

// GetStartedAt returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun.StartedAt, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun) GetStartedAt() *time.Time {
	return v.StartedAt
}

// GetCompletedAt returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun.CompletedAt, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun) GetCompletedAt() *time.Time {
	return v.CompletedAt
}

// GetPermalink returns getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun.Permalink, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionNodesPullRequestCommitsPullRequestCommitConnectionNodesPullRequestCommitCommitCheckSuitesCheckSuiteConnectionNodesCheckSuiteCheckRunsCheckRunConnectionNodesCheckRun) GetPermalink() string {
	return v.Permalink
}

// getLatestPRsRepositoryPullRequestsPullRequestConnectionPageInfo includes the requested fields of the GraphQL type PageInfo.
// The GraphQL type's documentation follows.
//
// Information about pagination in a connection.
type getLatestPRsRepositoryPullRequestsPullRequestConnectionPageInfo struct {
	// When paginating backwards, the cursor to continue.
	StartCursor *string `json:"startCursor"`
}

// GetStartCursor returns getLatestPRsRepositoryPullRequestsPullRequestConnectionPageInfo.StartCursor, and is useful for accessing the field via an interface.
func (v *getLatestPRsRepositoryPullRequestsPullRequestConnectionPageInfo) GetStartCursor() *string {
	return v.StartCursor
}

// getLatestPRsResponse is returned by getLatestPRs on success.
type getLatestPRsResponse struct {
	// Lookup a given repository by the owner and repository name.
	Repository *getLatestPRsRepository `json:"repository"`
}

// GetRepository returns getLatestPRsResponse.Repository, and is useful for accessing the field via an interface.
func (v *getLatestPRsResponse) GetRepository() *getLatestPRsRepository { return v.Repository }

func getLatestPRs(
	ctx context.Context,
	client graphql.Client,
	owner string,
	repo string,
	limit int,
	before *string,
) (*getLatestPRsResponse, error) {
	req := &graphql.Request{
		OpName: "getLatestPRs",
		Query: `
query getLatestPRs ($owner: String!, $repo: String!, $limit: Int!, $before: String) {
	repository(owner: $owner, name: $repo) {
		pullRequests(last: $limit, before: $before, states: MERGED) {
			pageInfo {
				startCursor
			}
			nodes {
				number
				mergedAt
				commits(last: 5) {
					nodes {
						commit {
							checkSuites(first: 15) {
								nodes {
									app {
										name
									}
									checkRuns(first: 50) {
										nodes {
											name
											conclusion
											startedAt
											completedAt
											permalink
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
`,
		Variables: &__getLatestPRsInput{
			Owner:  owner,
			Repo:   repo,
			Limit:  limit,
			Before: before,
		},
	}
	var err error

	var data getLatestPRsResponse
	resp := &graphql.Response{Data: &data}

	err = client.MakeRequest(
		ctx,
		req,
		resp,
	)

	return &data, err
}
