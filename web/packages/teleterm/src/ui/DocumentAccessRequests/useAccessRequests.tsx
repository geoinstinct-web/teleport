import { useState, useEffect } from 'react';

import * as types from 'teleterm/ui/services/workspacesService';
import useAttempt from 'shared/hooks/useAttemptNext';
import {
  AssumedRequest,
  LoggedInUser,
  AccessRequest as TshdAccessRequest,
} from 'teleterm/services/tshd/types';
import {
  makeAccessRequest,
  AccessRequest,
} from 'e-teleport/services/accessRequests';
import { RequestFlags } from 'e-teleport/AccessRequests/ReviewRequests';

import { useAppContext } from 'teleterm/ui/appContextProvider';
import { retryWithRelogin } from 'teleterm/ui/utils';
import { useWorkspaceContext } from 'teleterm/ui/Documents';
import { useWorkspaceLoggedInUser } from 'teleterm/ui/hooks/useLoggedInUser';
import { Timestamp } from 'gen-proto-ts/google/protobuf/timestamp_pb';

export default function useAccessRequests(doc: types.DocumentAccessRequests) {
  const ctx = useAppContext();
  ctx.clustersService.useState();

  const {
    localClusterUri: clusterUri,
    rootClusterUri,
    documentsService,
  } = useWorkspaceContext();

  const assumed = ctx.clustersService.getAssumedRequests(rootClusterUri);
  const loggedInUser = useWorkspaceLoggedInUser();
  const [accessRequests, setAccessRequests] = useState<AccessRequest[]>();
  const { attempt, setAttempt } = useAttempt('');

  function goBack() {
    documentsService.update(doc.uri, {
      title: `Access Requests`,
      state: 'browsing',
      requestId: '',
    });
  }

  function onViewRequest(requestId: string) {
    documentsService.update(doc.uri, {
      title: `Request: ${requestId}`,
      state: 'reviewing',
      requestId,
    });
  }

  const getRequests = async () => {
    try {
      const response = await retryWithRelogin(ctx, clusterUri, () =>
        ctx.clustersService.getAccessRequests(rootClusterUri)
      );
      setAttempt({ status: 'success' });
      // transform tshd access request to the webui access request and add flags
      const requests = response.map(r => makeUiAccessRequest(r));
      setAccessRequests(requests);
    } catch (err) {
      setAttempt({
        status: 'failed',
        statusText: err.message,
      });
    }
  };

  useEffect(() => {
    // only fetch when visitng RequestList
    if (doc.state === 'browsing') {
      getRequests();
    }
  }, [doc.state, clusterUri]);

  useEffect(() => {
    // if assumed object changes, we update which roles have been assumed in the table
    // this is mostly for using "Switchback" since that state is held outside this component
    setAccessRequests(prevState =>
      prevState?.map(r => ({
        ...r,
        isAssumed: assumed[r.id],
      }))
    );
  }, [assumed]);

  return {
    ctx,
    attempt,
    accessRequests,
    onViewRequest,
    doc,
    getRequests,
    getFlags: (accessRequest: AccessRequest) =>
      makeFlags(accessRequest, assumed, loggedInUser),
    goBack,
  };
}

export function makeUiAccessRequest(request: TshdAccessRequest) {
  return makeAccessRequest({
    ...request,
    created: Timestamp.toDate(request.created),
    expires: Timestamp.toDate(request.expires),
    maxDuration: request.maxDuration && Timestamp.toDate(request.maxDuration),
    requestTTL: request.requestTtl && Timestamp.toDate(request.requestTtl),
    sessionTTL: request.sessionTtl && Timestamp.toDate(request.sessionTtl),
    assumeStartTime:
      request.assumeStartTime && Timestamp.toDate(request.assumeStartTime),
    roles: request.roles,
    reviews: request.reviews.map(review => ({
      ...review,
      created: Timestamp.toDate(review.created),
      assumeStartTime:
        review.assumeStartTime && Timestamp.toDate(review.assumeStartTime),
    })),
    suggestedReviewers: request.suggestedReviewers,
    thresholdNames: request.thresholdNames,
    resources: request.resources,
  });
}

// transform tsdh Access Request type into the web's Access Request
// to promote code reuse
// TODO(gzdunek): Replace with a function from `DocumentAccessRequests/useReviewAccessRequest`.
export function makeFlags(
  request: AccessRequest,
  assumed: Record<string, AssumedRequest>,
  loggedInUser: LoggedInUser
): RequestFlags {
  const ownRequest = request.user === loggedInUser?.name;
  const canAssume = ownRequest && request.state === 'APPROVED';
  const isAssumed = !!assumed[request.id];

  const isPromoted =
    request.state === 'PROMOTED' && !!request.promotedAccessListTitle;

  const reviewed = request.reviews.find(r => r.author === loggedInUser?.name);
  const isPendingState = reviewed
    ? reviewed.state === 'PENDING'
    : request.state === 'PENDING';

  return {
    ...request,
    canAssume,
    isAssumed,
    canReview: !ownRequest && isPendingState,
    canDelete: true,
    ownRequest,
    isPromoted,
  };
}
