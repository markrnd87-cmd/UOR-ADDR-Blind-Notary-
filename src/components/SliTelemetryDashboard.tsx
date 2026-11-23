import React, { useMemo, useState } from 'react';
import {
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import {
  BlindTelemetryEvent,
  SliDistributionSlice,
  SliVerdictCategory,
  computeSliDistribution,
} from '../lib/notaryEngine';

export interface SliTelemetryDashboardProps {
  telemetryEvents: BlindTelemetryEvent[];
  onRecordSimulatedEvent: (category: SliVerdictCategory) => void;
  onResetTelemetry: () => void;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: SliDistributionSlice }>;
}

/**
 * Custom Recharts Tooltip rendering detailed SLI verdict metrics, kernel register bindings,
 * event share, latency statistics, and latest reason code.
 */
function SliPieTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload || payload.length === 0) {
    return null;
  }
  const slice = payload[0].payload;
  return (
    <div
      data-testid="sli-custom-tooltip"
      className="bg-white border border-slate-200 rounded-lg p-3.5 shadow-md text-xs space-y-1.5 min-w-[230px]"
    >
      <div className="flex items-center justify-between gap-3 pb-1.5 border-b border-slate-100">
        <div className="flex items-center gap-2">
          <span
            className="w-2.5 h-2.5 rounded-xs shrink-0"
            style={{ backgroundColor: slice.color }}
          />
          <span className="font-bold text-slate-900">{slice.label}</span>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-xs pt-0.5">
        <span className="text-slate-500">SLI Category:</span>
        <span className="text-right font-semibold text-slate-900">{slice.category}</span>

        <span className="text-slate-500">Kernel Verdict:</span>
        <span className="text-right font-semibold text-slate-900">{slice.verdictCode}</span>

        <span className="text-slate-500">Register:</span>
        <span className="text-right text-slate-700">{slice.registerBinding}</span>

        <span className="text-slate-500">Receipts:</span>
        <span className="text-right font-bold tabular-nums text-slate-900">
          {slice.count} ({slice.percentage.toFixed(1)}%)
        </span>

        <span className="text-slate-500">Avg / p95 Latency:</span>
        <span className="text-right tabular-nums text-slate-800">
          {slice.avgLatencyMicros} / {slice.p95LatencyMicros} µs
        </span>

        <span className="text-slate-500">Latest Reason:</span>
        <span className="text-right text-slate-700 truncate">{slice.latestReasonCode}</span>
      </div>
    </div>
  );
}

interface CustomLegendProps {
  slices: SliDistributionSlice[];
  activeCategory: 'all' | SliVerdictCategory;
  onSelectCategory: (category: SliVerdictCategory) => void;
}

/**
 * Custom Recharts Legend displaying interactive color swatches, SLI category names,
 * tabular receipt counts, percentage share, and average latency.
 */
function SliPieLegend({
  slices,
  activeCategory,
  onSelectCategory,
}: CustomLegendProps) {
  return (
    <div
      data-testid="sli-custom-legend"
      className="w-full grid grid-cols-1 sm:grid-cols-3 gap-2 pt-3 border-t border-slate-200 text-xs"
    >
      {slices.map((slice) => {
        const isSelected = activeCategory === slice.category;
        return (
          <button
            key={slice.category}
            type="button"
            onClick={() => onSelectCategory(slice.category)}
            className={`p-2.5 rounded-lg border text-left transition-colors ${
              isSelected
                ? 'border-slate-900 bg-white shadow-2xs'
                : 'border-slate-200/80 bg-white/70 hover:bg-white hover:border-slate-300'
            }`}
          >
            <div className="flex items-center gap-1.5">
              <span
                className="w-2.5 h-2.5 rounded-xs shrink-0"
                style={{ backgroundColor: slice.color }}
              />
              <span className="font-mono font-semibold text-slate-900 whitespace-nowrap">
                {slice.category}
              </span>
            </div>
            <p
              data-testid={`sli-slice-${slice.category}`}
              className="font-mono font-bold tabular-nums text-slate-900 mt-1"
            >
              {slice.count} ({slice.percentage.toFixed(1)}%)
            </p>
            <p className="text-[11px] font-mono tabular-nums text-slate-500 mt-0.5">
              {slice.registerBinding} · {slice.avgLatencyMicros} µs
            </p>
          </button>
        );
      })}
    </div>
  );
}

export function SliTelemetryDashboard({
  telemetryEvents,
  onRecordSimulatedEvent,
  onResetTelemetry,
}: SliTelemetryDashboardProps) {
  const [categoryFilter, setCategoryFilter] = useState<'all' | SliVerdictCategory>('all');

  const report = useMemo(
    () => computeSliDistribution(telemetryEvents),
    [telemetryEvents]
  );

  const filteredEvents = useMemo(() => {
    if (categoryFilter === 'all') return telemetryEvents;
    return telemetryEvents.filter((e) => e.sliCategory === categoryFilter);
  }, [telemetryEvents, categoryFilter]);

  const handleToggleCategory = (category: SliVerdictCategory) => {
    setCategoryFilter((prev) => (prev === category ? 'all' : category));
  };

  return (
    <section
      aria-label="Observability & SLI Verdict Telemetry Dashboard"
      className="bg-white border border-slate-200 rounded-xl p-6 space-y-6"
    >
      {/* Header & Interactive Telemetry Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-5 border-b border-slate-200">
        <div>
          <h2 className="text-lg font-bold text-slate-900">
            Observability Telemetry &amp; SLI Verdict Distribution (OB-01 .. OB-10)
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Visualizes blind notary SLI verdicts (verified, drift-blocked, tamper-blocked) from{' '}
            <span className="font-mono text-slate-700">telemetryEvents</span> while enforcing{' '}
            <span className="font-mono text-slate-700">Redacted := Withheld</span> across all payload streams.
          </p>
        </div>

        <div className="flex flex-wrap sm:flex-nowrap items-center gap-2 shrink-0">
          <button
            type="button"
            data-testid="record-verified-btn"
            onClick={() => onRecordSimulatedEvent('verified')}
            className="px-2.5 py-1.5 text-xs font-semibold text-emerald-800 bg-emerald-50 border border-emerald-200 rounded-lg hover:bg-emerald-100 transition-colors whitespace-nowrap shrink-0"
          >
            + Record Verified
          </button>
          <button
            type="button"
            data-testid="record-drift-btn"
            onClick={() => onRecordSimulatedEvent('drift-blocked')}
            className="px-2.5 py-1.5 text-xs font-semibold text-amber-800 bg-amber-50 border border-amber-200 rounded-lg hover:bg-amber-100 transition-colors whitespace-nowrap shrink-0"
          >
            + Record Drift-Blocked
          </button>
          <button
            type="button"
            data-testid="record-tamper-btn"
            onClick={() => onRecordSimulatedEvent('tamper-blocked')}
            className="px-2.5 py-1.5 text-xs font-semibold text-red-800 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition-colors whitespace-nowrap shrink-0"
          >
            + Record Tamper-Blocked
          </button>
          <button
            type="button"
            onClick={onResetTelemetry}
            className="px-2.5 py-1.5 text-xs font-semibold text-slate-700 bg-slate-100 border border-slate-200 rounded-lg hover:bg-slate-200 transition-colors whitespace-nowrap shrink-0"
          >
            Reset Sample
          </button>
        </div>
      </div>

      {/* Main Chart + Breakdown Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        {/* Recharts Pie Chart Visualization with Custom Tooltip & Custom Legend */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center bg-slate-50 border border-slate-200 rounded-xl p-5">
          <div className="w-full flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-700">
              SLI Verdict Distribution (Recharts PieChart)
            </span>
            <span
              data-testid="sli-total-events"
              className="text-xs font-mono font-bold tabular-nums text-slate-900"
            >
              n = {report.totalEvents} receipts
            </span>
          </div>

          <div
            data-testid="sli-recharts-pie-container"
            className="w-full h-80 min-h-[320px]"
          >
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={report.slices}
                  dataKey="count"
                  nameKey="label"
                  cx="50%"
                  cy="45%"
                  innerRadius={56}
                  outerRadius={92}
                  paddingAngle={2}
                  stroke="#ffffff"
                  strokeWidth={2}
                  isAnimationActive={false}
                  onClick={(_data, index) => {
                    const clicked = report.slices[index];
                    if (clicked) {
                      handleToggleCategory(clicked.category);
                    }
                  }}
                >
                  {report.slices.map((slice) => (
                    <Cell
                      key={slice.category}
                      fill={slice.color}
                      opacity={
                        categoryFilter === 'all' || categoryFilter === slice.category
                          ? 1
                          : 0.35
                      }
                      style={{ cursor: 'pointer' }}
                    />
                  ))}
                </Pie>
                <Tooltip content={<SliPieTooltip />} />
                <Legend
                  verticalAlign="bottom"
                  content={() => (
                    <SliPieLegend
                      slices={report.slices}
                      activeCategory={categoryFilter}
                      onSelectCategory={handleToggleCategory}
                    />
                  )}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* SLI Metrics & Breakdown Table */}
        <div className="lg:col-span-7 space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
              <p className="text-xs text-slate-500">Verified Pass Share (OB-05)</p>
              <p
                data-testid="sli-verified-pct"
                className="text-xl font-bold font-mono tabular-nums text-emerald-700 mt-1"
              >
                {report.verifiedRatePct.toFixed(1)}%
              </p>
              <p className="text-xs font-mono text-slate-600 mt-1">
                {report.verifiedCount} / {report.totalEvents} pinned invocations
              </p>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
              <p className="text-xs text-slate-500">Drift &amp; Tamper Intercepts</p>
              <p
                data-testid="sli-blocked-total"
                className="text-xl font-bold font-mono tabular-nums text-red-700 mt-1"
              >
                {report.driftBlockedCount + report.tamperBlockedCount} blocked
              </p>
              <p className="text-xs font-mono text-slate-600 mt-1">
                {report.driftBlockedCount} drift · {report.tamperBlockedCount} tamper
              </p>
            </div>

            <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl">
              <p className="text-xs text-slate-500">p95 Admission Latency (OB-08)</p>
              <p className="text-xl font-bold font-mono tabular-nums text-slate-900 mt-1">
                {report.p95LatencyMicros} µs
              </p>
              <p className="text-xs font-mono text-slate-600 mt-1">
                Target SLO &le; 1500 µs (OV-05)
              </p>
            </div>
          </div>

          {/* Verdict Breakdown Table */}
          <div className="overflow-x-auto border border-slate-200 rounded-xl">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-200 bg-slate-50 text-xs font-semibold text-slate-600">
                  <th className="py-2.5 px-4">SLI Verdict Category</th>
                  <th className="py-2.5 px-4">Kernel Verdict Code</th>
                  <th className="py-2.5 px-4">Register Binding</th>
                  <th className="py-2.5 px-4 text-right">Events</th>
                  <th className="py-2.5 px-4 text-right">Share</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 text-xs">
                {report.slices.map((slice) => (
                  <tr
                    key={slice.category}
                    onClick={() => handleToggleCategory(slice.category)}
                    className={`cursor-pointer transition-colors ${
                      categoryFilter === slice.category
                        ? 'bg-slate-100'
                        : 'hover:bg-slate-50'
                    }`}
                  >
                    <td className="py-2.5 px-4 font-semibold text-slate-900">
                      <div className="flex items-center gap-2">
                        <span
                          className="w-2.5 h-2.5 rounded-xs shrink-0"
                          style={{ backgroundColor: slice.color }}
                        />
                        <span>{slice.label}</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-800">
                      {slice.verdictCode}
                    </td>
                    <td className="py-2.5 px-4 font-mono text-slate-600">
                      {slice.registerBinding}
                    </td>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-right font-bold text-slate-900">
                      {slice.count}
                    </td>
                    <td className="py-2.5 px-4 font-mono tabular-nums text-right text-slate-700">
                      {slice.percentage.toFixed(1)}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Blind AuditEvent Log Stream (OB-01..OB-04) */}
      <div className="pt-4 border-t border-slate-200 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
          <div>
            <h3 className="text-sm font-bold text-slate-900">
              Blind Telemetry AuditEvent Stream (UorNotary.Observability.AuditEvent)
            </h3>
            <p className="text-xs text-slate-500">
              Click any PieChart sector or custom legend card to filter by verdict category, or hover sectors for detailed tooltips.
            </p>
          </div>
          {categoryFilter !== 'all' && (
            <button
              type="button"
              onClick={() => setCategoryFilter('all')}
              className="text-xs font-mono font-semibold text-slate-700 underline self-start sm:self-auto"
            >
              Show all categories ({telemetryEvents.length})
            </button>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-200 text-xs font-semibold text-slate-600">
                <th className="py-2.5 pr-4">Timestamp</th>
                <th className="py-2.5 px-4">Server ID</th>
                <th className="py-2.5 px-4">SLI Verdict</th>
                <th className="py-2.5 px-4">Reason Code</th>
                <th className="py-2.5 px-4">71-Byte Manifest Kappa</th>
                <th className="py-2.5 px-4 text-right">Latency</th>
                <th className="py-2.5 pl-4">Payload Prose</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 text-xs font-mono">
              {filteredEvents.slice(0, 8).map((ev) => (
                <tr key={ev.eventId} className="hover:bg-slate-50">
                  <td className="py-2.5 pr-4 text-slate-600 whitespace-nowrap">
                    {ev.timestamp}
                  </td>
                  <td className="py-2.5 px-4 font-semibold text-slate-900">
                    {ev.serverId}
                  </td>
                  <td
                    className={`py-2.5 px-4 font-bold ${
                      ev.sliCategory === 'verified'
                        ? 'text-emerald-700'
                        : ev.sliCategory === 'drift-blocked'
                        ? 'text-amber-700'
                        : 'text-red-700'
                    }`}
                  >
                    {ev.sliCategory}
                  </td>
                  <td className="py-2.5 px-4 text-slate-700">{ev.reasonCode}</td>
                  <td className="py-2.5 px-4 tabular-nums text-slate-600 truncate max-w-[220px]">
                    {ev.manifestKappa}
                  </td>
                  <td className="py-2.5 px-4 tabular-nums text-right text-slate-800">
                    {ev.latencyMicros} µs
                  </td>
                  <td className="py-2.5 pl-4 text-slate-500">
                    Redacted::{ev.rawPayloadRedacted}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

export default SliTelemetryDashboard;
