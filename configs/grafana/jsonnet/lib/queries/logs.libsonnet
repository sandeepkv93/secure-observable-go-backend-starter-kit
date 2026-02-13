local c = import 'common.libsonnet';

local selector = '{service_name="%s"}' % c.serviceName;

{
  appLogs: selector,
  warningLogs: '%s | json | level="warn"' % selector,
  requestLogs: '%s | json | message="http.request"' % selector,
  traceCorrelatedLogs: '%s | json | trace_id!=""' % selector,

  errorCountLastHour: 'sum(count_over_time(%s | json | level="error" [1h]))' % selector,
  warningCountLastHour: 'sum(count_over_time(%s | json | level="warn" [1h]))' % selector,
  requestCountLastHour: 'sum(count_over_time(%s | json | message="http.request" [1h]))' % selector,
  uniqueTraceIDsLastHour: 'count(sum by (trace_id) (count_over_time(%s | json | trace_id!="" [1h])))' % selector,

  logVolumeError: 'sum(count_over_time(%s | json | level="error" [5m]))' % selector,
  logVolumeWarn: 'sum(count_over_time(%s | json | level="warn" [5m]))' % selector,
  logVolumeInfo: 'sum(count_over_time(%s | json | level="info" [5m]))' % selector,
  logVolumeDebug: 'sum(count_over_time(%s | json | level="debug" [5m]))' % selector,

  status2xx: 'sum(count_over_time(%s | json | status >= 200 and status < 300 [5m]))' % selector,
  status4xx: 'sum(count_over_time(%s | json | status >= 400 and status < 500 [5m]))' % selector,
  status5xx: 'sum(count_over_time(%s | json | status >= 500 and status < 600 [5m]))' % selector,

  errorByLevel: 'sum by (level) (count_over_time(%s | json | level=~"error|warn" [5m]))' % selector,
}
