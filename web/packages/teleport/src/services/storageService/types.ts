/*
Copyright 2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

export const KeysEnum = {
  TOKEN: 'grv_teleport_token',
  TOKEN_RENEW: 'grv_teleport_token_renew',
  LAST_ACTIVE: 'grv_teleport_last_active',
  DISCOVER: 'grv_teleport_discover',
  THEME: 'grv_teleport_ui_theme',
  SHOW_ASSIST_POPUP: 'grv_teleport_show_assist',
  ASSIST_VIEW_MODE: 'grv_teleport_assist_view_mode',
  USER_PREFERENCES: 'grv_teleport_user_preferences',
  ONBOARD_SURVEY: 'grv_teleport_onboard_survey',
  RECOMMEND_FEATURE: 'grv_recommend_feature',
  UNIFIED_RESOURCES_DISABLED: 'grv_teleport_unified_resources_disabled',
  UNIFIED_RESOURCES_NOT_SUPPORTED:
    'grv_teleport_unified_resources_not_supported',
  PINNED_RESOURCES_NOT_SUPPORTED: 'grv_teleport_pinned_resources_not_supported',
  CLOUD_USER_INVITES: 'grv_teleport_cloud_user_invites',
  ACCESS_GRAPH_SEARCH_MODE: 'grv_teleport_access_graph_search_mode',
  ACCESS_GRAPH_QUERY: 'grv_teleport_access_graph_query',
  ACCESS_GRAPH_ENABLED: 'grv_teleport_access_graph_enabled',
  ACCESS_GRAPH_SQL_ENABLED: 'grv_teleport_access_graph_sql_enabled',
};

// SurveyRequest is the request for sending data to the back end
export type SurveyRequest = {
  companyName: string;
  employeeCount: string;
  resourcesList: Array<string>;
  role: string;
  team: string;
};

// LocalStorageSurvey is the SurveyRequest type defined in Enterprise
export type LocalStorageSurvey = SurveyRequest & {
  clusterResources: Array<number>;
  marketingParams: LocalStorageMarketingParams;
};

// LocalStorageMarketingParams is the MarketingParams type defined in Enterprise
export type LocalStorageMarketingParams = {
  campaign: string;
  source: string;
  medium: string;
  intent: string;
};

// CloudUserInvites is a set of users and roles which should be submitted after
// initial login.
export type CloudUserInvites = {
  recipients: Array<string>;
  roles: Array<string>;
};
