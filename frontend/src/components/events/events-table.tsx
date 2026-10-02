import { useMemo, useState, type KeyboardEvent, type ReactNode } from 'react';
import {
  columnVisibilityFeature,
  createColumnHelper,
  rowSortingFeature,
  tableFeatures,
  useTable,
  type SortingState,
  type Updater,
  type ColumnVisibilityState,
} from '@tanstack/react-table';
import { ArrowDown, ArrowUp, Columns3, Filter } from 'lucide-react';
import type { EventHit } from '@/api/events';
import { SeverityBadge } from '@/components/events/severity-badge';
import { fieldText, formatEventTime } from '@/lib/event-fields';
import { hasFilterValue, type DrillField, type EventFilters } from '@/lib/event-filters';
import { cn } from '@/lib/utils';

// The events table, headless through TanStack Table: the backend filters, sorts and pages, so
// the table is in manual mode and only owns which columns show and which way time runs.

const features = tableFeatures({ rowSortingFeature, columnVisibilityFeature });
const helper = createColumnHelper<typeof features, EventHit>();

/** Hidden until asked for: rarely what a first look needs, and the table stays narrow. */
const INITIAL_VISIBILITY: ColumnVisibilityState = { sourceId: false, request: false };

const NO_HITS: EventHit[] = [];

interface EventsTableProps {
  hits: EventHit[] | undefined;
  filters: EventFilters;
  /** Narrows the search to `value` of `field` as well. */
  onDrill: (field: DrillField, value: string | number) => void;
  onOrderChange: (order: EventFilters['order']) => void;
  /** Opens the details of a row. */
  onSelect: (hit: EventHit) => void;
  selectedId: number | undefined;
  /** Dimmed while a new page or filter loads in place of these rows. */
  stale?: boolean;
}

/**
 * A value that narrows the search when clicked. The click stays on the value: the row behind
 * it opens the details.
 */
function DrillValue({
  field,
  value,
  filters,
  onDrill,
  children,
  className,
}: {
  field: DrillField;
  value: string | number;
  filters: EventFilters;
  onDrill: EventsTableProps['onDrill'];
  children: ReactNode;
  className?: string;
}) {
  const active = hasFilterValue(filters, field, value);
  return (
    <button
      type="button"
      disabled={active}
      title={active ? 'Already filtered on this value' : 'Show only events with this value'}
      aria-label={`Filter by ${String(value)}`}
      onClick={(event) => {
        event.stopPropagation();
        onDrill(field, value);
      }}
      onKeyDown={(event) => event.stopPropagation()}
      className={cn(
        'group/drill hover:bg-accent focus-visible:ring-ring/50 -mx-1 inline-flex items-center gap-1 rounded px-1 py-0.5 text-left whitespace-nowrap outline-none focus-visible:ring-[3px] disabled:cursor-default disabled:hover:bg-transparent',
        className,
      )}
    >
      {children}
      {!active && (
        <Filter
          aria-hidden
          className="text-muted-foreground size-3 shrink-0 opacity-0 group-hover/drill:opacity-100 group-focus-visible/drill:opacity-100"
        />
      )}
    </button>
  );
}

export function EventsTable({
  hits,
  filters,
  onDrill,
  onOrderChange,
  onSelect,
  selectedId,
  stale,
}: EventsTableProps) {
  const columns = useMemo(
    () =>
      helper.columns([
        helper.accessor('occurredAt', {
          header: 'Time',
          enableHiding: false,
          cell: (info) => (
            <time dateTime={info.getValue()} className="whitespace-nowrap tabular-nums">
              {formatEventTime(info.getValue())}
            </time>
          ),
        }),
        helper.accessor('severity', {
          header: 'Severity',
          enableSorting: false,
          cell: (info) => {
            const severity = info.getValue();
            return severity ? (
              <DrillValue field="severity" value={severity} filters={filters} onDrill={onDrill}>
                <SeverityBadge severity={severity} />
              </DrillValue>
            ) : (
              <SeverityBadge severity={undefined} />
            );
          },
        }),
        helper.accessor('sourceId', {
          header: 'Source',
          enableSorting: false,
          cell: (info) => {
            const id = info.getValue();
            return id === undefined ? (
              '—'
            ) : (
              <DrillValue field="sourceId" value={id} filters={filters} onDrill={onDrill}>
                #{id}
              </DrillValue>
            );
          },
        }),
        helper.accessor((hit) => fieldText(hit.fields, 'host'), {
          id: 'host',
          header: 'Host',
          enableSorting: false,
          cell: (info) => (
            <span
              className="block max-w-40 truncate py-0.5 font-mono text-xs"
              title={info.getValue()}
            >
              {info.getValue() ?? '—'}
            </span>
          ),
        }),
        helper.accessor((hit) => fieldText(hit.fields, 'srcIp'), {
          id: 'srcIp',
          header: 'Source IP',
          enableSorting: false,
          cell: (info) => {
            const ip = info.getValue();
            return ip ? (
              <DrillValue
                field="srcIp"
                value={ip}
                filters={filters}
                onDrill={onDrill}
                className="font-mono text-xs"
              >
                {ip}
              </DrillValue>
            ) : (
              '—'
            );
          },
        }),
        helper.accessor(
          (hit) =>
            [fieldText(hit.fields, 'method'), fieldText(hit.fields, 'path')]
              .filter(Boolean)
              .join(' ') || undefined,
          {
            id: 'request',
            header: 'Request',
            enableSorting: false,
            cell: (info) => (
              <span
                className="block max-w-56 truncate py-0.5 font-mono text-xs"
                title={info.getValue()}
              >
                {info.getValue() ?? '—'}
              </span>
            ),
          },
        ),
        helper.accessor((hit) => fieldText(hit.fields, 'status'), {
          id: 'status',
          header: 'Status',
          enableSorting: false,
          cell: (info) => {
            const status = info.getValue();
            return status ? (
              <DrillValue
                field="status"
                value={status}
                filters={filters}
                onDrill={onDrill}
                className={cn(
                  'font-mono text-xs tabular-nums',
                  status.startsWith('5') && 'text-destructive font-semibold',
                  status.startsWith('4') && 'text-orange-700 dark:text-orange-300',
                )}
              >
                {status}
              </DrillValue>
            ) : (
              '—'
            );
          },
        }),
        helper.accessor('message', {
          header: 'Message',
          enableSorting: false,
          enableHiding: false,
          cell: (info) => (
            <span className="line-clamp-2 min-w-48 wrap-anywhere" title={info.getValue()}>
              {info.getValue() || <span className="text-muted-foreground">(no message)</span>}
            </span>
          ),
        }),
      ]),
    [filters, onDrill],
  );

  // Time is the one sort the backend offers; the table shows it and hands a change back.
  const sorting = useMemo<SortingState>(
    () => [{ id: 'occurredAt', desc: filters.order === 'desc' }],
    [filters.order],
  );
  const [columnVisibility, setColumnVisibility] =
    useState<ColumnVisibilityState>(INITIAL_VISIBILITY);

  const table = useTable({
    features,
    columns,
    data: hits ?? NO_HITS,
    getRowId: (hit, index) => String(hit.eventId ?? `row-${index}`),
    manualSorting: true,
    enableSortingRemoval: false,
    state: { sorting, columnVisibility },
    onSortingChange: (updater: Updater<SortingState>) => {
      const next = typeof updater === 'function' ? updater(sorting) : updater;
      onOrderChange(next[0]?.desc === false ? 'asc' : 'desc');
    },
    onColumnVisibilityChange: setColumnVisibility,
  });

  function openOnKey(event: KeyboardEvent<HTMLTableRowElement>, hit: EventHit) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      onSelect(hit);
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2 px-4 pt-3">
        <p className="text-muted-foreground text-xs">
          Select a row for every field of the event; select a value to filter on it.
        </p>
        <ColumnPicker table={table} />
      </div>
      <div className="overflow-x-auto">
        <table
          className={cn('w-full text-sm transition-opacity', stale && 'opacity-60')}
          aria-busy={stale}
        >
          <caption className="sr-only">
            Matching events. Select a row to see every field of the event.
          </caption>
          <thead className="text-muted-foreground border-b text-left">
            {table.getHeaderGroups().map((group) => (
              <tr key={group.id}>
                {group.headers.map((header) => {
                  const sorted = header.column.getIsSorted();
                  return (
                    <th
                      key={header.id}
                      scope="col"
                      aria-sort={
                        sorted === 'asc'
                          ? 'ascending'
                          : sorted === 'desc'
                            ? 'descending'
                            : undefined
                      }
                      className="px-4 py-3 font-medium whitespace-nowrap"
                    >
                      {header.isPlaceholder ? null : header.column.getCanSort() ? (
                        <button
                          type="button"
                          onClick={header.column.getToggleSortingHandler()}
                          title={sorted === 'desc' ? 'Show oldest first' : 'Show newest first'}
                          className="hover:text-foreground inline-flex items-center gap-1"
                        >
                          <table.FlexRender header={header} />
                          {sorted === 'asc' ? (
                            <ArrowUp aria-hidden className="size-3.5" />
                          ) : (
                            <ArrowDown aria-hidden className="size-3.5" />
                          )}
                        </button>
                      ) : (
                        <table.FlexRender header={header} />
                      )}
                    </th>
                  );
                })}
              </tr>
            ))}
          </thead>
          <tbody className="divide-y">
            {table.getRowModel().rows.map((row) => {
              const hit = row.original;
              const selected = hit.eventId !== undefined && hit.eventId === selectedId;
              return (
                <tr
                  key={row.id}
                  tabIndex={0}
                  aria-selected={selected}
                  aria-label={`Event ${hit.eventId ?? ''} at ${formatEventTime(hit.occurredAt)}`}
                  onClick={() => onSelect(hit)}
                  onKeyDown={(event) => openOnKey(event, hit)}
                  className={cn(
                    'hover:bg-muted/50 focus-visible:bg-muted/50 focus-visible:ring-ring/50 cursor-pointer align-top outline-none focus-visible:ring-2 focus-visible:ring-inset',
                    selected && 'bg-muted',
                  )}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-4 py-2.5">
                      <table.FlexRender cell={cell} />
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

type EventsTableInstance = ReturnType<typeof useTable<typeof features, EventHit>>;

/** Shows or hides the optional columns. */
function ColumnPicker({ table }: { table: EventsTableInstance }) {
  return (
    <details className="relative">
      <summary className="hover:bg-accent text-muted-foreground inline-flex cursor-pointer list-none items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs select-none">
        <Columns3 aria-hidden className="size-3.5" />
        Columns
      </summary>
      <fieldset className="bg-popover text-popover-foreground absolute right-0 z-10 mt-1 w-44 space-y-1 rounded-md border p-2 text-sm shadow-md">
        <legend className="sr-only">Visible columns</legend>
        {table
          .getAllLeafColumns()
          .filter((column) => column.getCanHide())
          .map((column) => (
            <label
              key={column.id}
              className="hover:bg-accent flex items-center gap-2 rounded px-1.5 py-1"
            >
              <input
                type="checkbox"
                checked={column.getIsVisible()}
                onChange={(event) => column.toggleVisibility(event.target.checked)}
              />
              {typeof column.columnDef.header === 'string' ? column.columnDef.header : column.id}
            </label>
          ))}
      </fieldset>
    </details>
  );
}
