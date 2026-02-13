local c = import 'common.libsonnet';

local selector = '{service_name="%s"}' % c.serviceName;

{
  traceCorrelatedLogRate: 'sum(rate(%s | json | trace_id!="" [5m]))' % selector,
  authRequestP95: 'histogram_quantile(0.95, sum(rate(auth_request_duration_seconds_bucket{job="%s"}[5m])) by (le, endpoint))' % c.job,
  traceEventsByType: 'sum by (path) (rate(%s | json | trace_id!="" | path!="" [5m]))' % selector,
  recentTraceCorrelatedLogs: '%s | json | trace_id!=""' % selector,

  uniqueTraceIDsLastHour: 'count(sum by (trace_id) (count_over_time(%s | json | trace_id!="" [1h])))' % selector,
  traceStatus2xxRate: 'sum(rate(%s | json | trace_id!="" | status >= 200 and status < 300 [5m]))' % selector,
  traceStatus4xxRate: 'sum(rate(%s | json | trace_id!="" | status >= 400 and status < 500 [5m]))' % selector,
  traceStatus5xxRate: 'sum(rate(%s | json | trace_id!="" | status >= 500 and status < 600 [5m]))' % selector,
  traceLinkedRequests: 'sum(rate(%s | json | trace_id!="" | message="http.request" [5m]))' % selector,
}
