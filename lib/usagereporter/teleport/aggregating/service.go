// Copyright 2023 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aggregating

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/gravitational/trace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	prehogv1 "github.com/gravitational/teleport/gen/proto/go/prehog/v1"
	"github.com/gravitational/teleport/lib/backend"
)

const (
	// maxItemSize is the maximum size for a backend value; dynamodb has a limit of
	// 400KiB per item, we store values in base64, there's some framing, and a
	// healthy 50% margin gets us to about 128KiB.
	maxItemSize = 128 * 1024
)

const (
	userActivityReportsPrefix     = "userActivityReports"
	userActivityReportsLock       = "userActivityReportsLock"
	ResourcePresenceReportsPrefix = "resourcePresenceReports"
)

// userActivityReportKey returns the backend key for a user activity report with
// a given UUID and start time, such that reports with an earlier start time
// will appear earlier in lexicographic ordering.
func userActivityReportKey(reportUUID uuid.UUID, startTime time.Time) []byte {
	return backend.Key(userActivityReportsPrefix, startTime.Format(time.RFC3339), reportUUID.String())
}

func prepareUserActivityReport(
	clusterName, reporterHostID []byte,
	startTime time.Time, records []*prehogv1.UserActivityRecord,
) (*prehogv1.UserActivityReport, error) {
	reportUUID := uuid.New()
	report := &prehogv1.UserActivityReport{
		ReportUuid:     reportUUID[:],
		ClusterName:    clusterName,
		ReporterHostid: reporterHostID,
		StartTime:      timestamppb.New(startTime),
		Records:        records,
	}

	for proto.Size(report) > maxItemSize {
		if len(report.Records) <= 1 {
			return nil, trace.LimitExceeded("failed to marshal user activity report within size limit (this is a bug)")
		}

		report.Records = report.Records[:len(report.Records)/2]
	}

	return report, nil
}

// resourcePresenceReportKey returns the backend key for a resource presence report with
// a given UUID and start time, such that reports with an earlier start time
// will appear earlier in lexicographic ordering.
func resourcePresenceReportKey(reportUUID uuid.UUID, startTime time.Time) []byte {
	return backend.Key(ResourcePresenceReportsPrefix, startTime.Format(time.RFC3339), reportUUID.String())
}

// prepareResourcePresenceReport prepares a resource presence report for storage.
// It returns a slice of reports for case when single report is too large to fit in a single item.
// As even a single resource kind report can be too large to fit in a single item, it may return
// multiple reports with single resource kind report split into multiple fragments.
func prepareResourcePresenceReports(
	clusterName, reporterHostID []byte,
	startTime time.Time, records []*prehogv1.ResourceKindPresenceReport,
) ([]*prehogv1.ResourcePresenceReport, error) {
	reports := make([]*prehogv1.ResourcePresenceReport, 0, 1) // at least one report

	for len(records) > 0 {
		reportUUID := uuid.New()
		report := &prehogv1.ResourcePresenceReport{
			ReportUuid:          reportUUID[:],
			ClusterName:         clusterName,
			ReporterHostid:      reporterHostID,
			StartTime:           timestamppb.New(startTime),
			ResourceKindReports: records,
		}

		if proto.Size(report) <= maxItemSize {
			// The last report fits, so we're done.
			reports = append(reports, report)
			return reports, nil
		}

		// We're over the size limit, so we need to split the report and try again.
		report.ResourceKindReports = make([]*prehogv1.ResourceKindPresenceReport, 0, len(records)-1)

		emptyKindReportSize := proto.Size(&prehogv1.ResourceKindPresenceReport{
			ResourceKind: records[0].GetResourceKind(),
			ResourceIds:  make([]uint64, 1), // need to have non-empty slice to calculate size
		})
		const singleItemSize = 8

		for _, kindReport := range records {
			if proto.Size(report)+proto.Size(kindReport) <= maxItemSize {
				// This kind report fits, so we're done.
				report.ResourceKindReports = append(report.ResourceKindReports, kindReport)
				records = records[1:]
				continue // try next kind report
			}

			freeSize := maxItemSize - proto.Size(report)
			elementsToFit := (freeSize - emptyKindReportSize) / singleItemSize
			if elementsToFit <= 0 {
				// This kind report is too big to fit even if we remove all elements,
				break // try to insert it into next report
			}

			// Split the kind report into two fragments, the first of which will be
			// added to the current report, and the second of which will be added to
			// the next report.
			kindReport1 := &prehogv1.ResourceKindPresenceReport{
				ResourceKind: kindReport.GetResourceKind(),
				ResourceIds:  kindReport.GetResourceIds()[:elementsToFit],
			}

			// Add the first fragment to the current report.
			report.ResourceKindReports = append(report.ResourceKindReports, kindReport1)

			kindReport2 := &prehogv1.ResourceKindPresenceReport{
				ResourceKind: kindReport.GetResourceKind(),
				ResourceIds:  kindReport.GetResourceIds()[elementsToFit:],
			}

			records = append([]*prehogv1.ResourceKindPresenceReport{kindReport2}, records[1:]...)
		}

		// Sanity check that report is still fits
		if proto.Size(report) > maxItemSize {
			return nil, trace.LimitExceeded("failed to marshal resource presence report of %d within size limit of %d bytes (this is a bug)", proto.Size(report), maxItemSize)
		}

		reports = append(reports, report)
	}

	return reports, nil
}

// reportService is a [backend.Backend] wrapper that handles usage reports.
type reportService struct {
	b backend.Backend
}

func (r reportService) upsertUserActivityReport(ctx context.Context, report *prehogv1.UserActivityReport, ttl time.Duration) error {
	wire, err := proto.Marshal(report)
	if err != nil {
		return trace.Wrap(err)
	}

	reportUUID, err := uuid.FromBytes(report.GetReportUuid())
	if err != nil {
		return trace.Wrap(err)
	}

	startTime := report.GetStartTime().AsTime()
	if startTime.IsZero() {
		return trace.BadParameter("missing start_time")
	}

	if _, err := r.b.Put(ctx, backend.Item{
		Key:     userActivityReportKey(reportUUID, startTime),
		Value:   wire,
		Expires: startTime.Add(ttl),
	}); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (r reportService) deleteUserActivityReport(ctx context.Context, report *prehogv1.UserActivityReport) error {
	reportUUID, err := uuid.FromBytes(report.GetReportUuid())
	if err != nil {
		return trace.Wrap(err)
	}

	startTime := report.GetStartTime().AsTime()
	if startTime.IsZero() {
		return trace.BadParameter("missing start_time")
	}

	if err := r.b.Delete(ctx, userActivityReportKey(reportUUID, startTime)); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// listUserActivityReports returns the first `count` user activity reports
// according to the key order; as we store them with time and uuid in the key,
// this results in returning earlier reports first.
func (r reportService) listUserActivityReports(ctx context.Context, count int) ([]*prehogv1.UserActivityReport, error) {
	rangeStart := backend.ExactKey(userActivityReportsPrefix)
	result, err := r.b.GetRange(ctx, rangeStart, backend.RangeEnd(rangeStart), count)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	reports := make([]*prehogv1.UserActivityReport, 0, len(result.Items))
	for _, item := range result.Items {
		report := &prehogv1.UserActivityReport{}
		if err := proto.Unmarshal(item.Value, report); err != nil {
			return nil, trace.Wrap(err)
		}
		reports = append(reports, report)
	}

	return reports, nil
}

func (r reportService) createUserActivityReportsLock(ctx context.Context, ttl time.Duration, payload []byte) error {
	if len(payload) == 0 {
		payload = []byte("null")
	}
	if _, err := r.b.Create(ctx, backend.Item{
		Key:     backend.Key(userActivityReportsLock),
		Value:   payload,
		Expires: r.b.Clock().Now().UTC().Add(ttl),
	}); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (r reportService) upsertResourcePresenceReport(ctx context.Context, report *prehogv1.ResourcePresenceReport, ttl time.Duration) error {
	wire, err := proto.Marshal(report)
	if err != nil {
		return trace.Wrap(err)
	}

	reportUUID, err := uuid.FromBytes(report.GetReportUuid())
	if err != nil {
		return trace.Wrap(err)
	}

	startTime := report.GetStartTime().AsTime()
	if startTime.IsZero() {
		return trace.BadParameter("missing start_time")
	}

	if _, err := r.b.Put(ctx, backend.Item{
		Key:     resourcePresenceReportKey(reportUUID, startTime),
		Value:   wire,
		Expires: startTime.Add(ttl),
	}); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (r reportService) deleteResourcePresenceReport(ctx context.Context, report *prehogv1.ResourcePresenceReport) error {
	reportUUID, err := uuid.FromBytes(report.GetReportUuid())
	if err != nil {
		return trace.Wrap(err)
	}

	startTime := report.GetStartTime().AsTime()
	if startTime.IsZero() {
		return trace.BadParameter("missing start_time")
	}

	if err := r.b.Delete(ctx, resourcePresenceReportKey(reportUUID, startTime)); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// listResourcePresenceReports returns the first `count` resource counts reports
// according to the key order; as we store them with time and uuid in the key,
// this results in returning earlier reports first.
func (r reportService) listResourcePresenceReports(ctx context.Context, count int) ([]*prehogv1.ResourcePresenceReport, error) {
	rangeStart := backend.ExactKey(ResourcePresenceReportsPrefix)
	result, err := r.b.GetRange(ctx, rangeStart, backend.RangeEnd(rangeStart), count)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	reports := make([]*prehogv1.ResourcePresenceReport, 0, len(result.Items))
	for _, item := range result.Items {
		report := &prehogv1.ResourcePresenceReport{}
		if err := proto.Unmarshal(item.Value, report); err != nil {
			return nil, trace.Wrap(err)
		}
		reports = append(reports, report)
	}

	return reports, nil
}
