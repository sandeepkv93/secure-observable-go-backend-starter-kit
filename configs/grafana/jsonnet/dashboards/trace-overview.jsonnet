local dashboard = import '../lib/dashboard.libsonnet';
local panels = import '../lib/panels.libsonnet';
local q = import '../lib/queries/traces.libsonnet';

local panelList = [
  panels.stat(1, 'Trace-Correlated Log Rate', 0, 0, 6, 6, 'loki', 'loki', q.traceCorrelatedLogRate, 'reqps', null, 'range'),
  panels.stat(2, 'Auth Request p95', 6, 0, 6, 6, 'prometheus', 'mimir', q.authRequestP95, 's', 'p95'),
  panels.stat(3, 'Unique Trace IDs (1h)', 12, 0, 6, 6, 'loki', 'loki', q.uniqueTraceIDsLastHour, 'short', null, 'range'),
  panels.stat(4, 'Trace-Linked Requests', 18, 0, 6, 6, 'loki', 'loki', q.traceLinkedRequests, 'reqps', null, 'range'),

  panels.timeseries(5, 'Trace-Correlated Request Paths', 0, 6, 24, 8, 'loki', 'loki', q.traceEventsByType, '{{path}}', null, null, null, 'range'),

  panels.timeseriesTargets(6, 'Trace-Correlated Status-Class Rate', 0, 14, 24, 8, 'loki', 'loki', [
    panels.target('A', q.traceStatus2xxRate, '2xx', 'range'),
    panels.target('B', q.traceStatus4xxRate, '4xx', 'range'),
    panels.target('C', q.traceStatus5xxRate, '5xx', 'range'),
  ], 'reqps'),

  panels.logs(7, 'Recent Trace-Correlated Logs', 0, 22, 24, 10, q.recentTraceCorrelatedLogs, 'range'),
];

dashboard.new('Trace Overview', 'trace-overview', 3, ['otel', 'traces', 'correlation', 'tempo'], panelList)
