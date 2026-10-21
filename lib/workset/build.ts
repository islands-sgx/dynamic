import {
  canonicalEffects,
  Effect,
  formatRva,
  PAGE_SIZE,
  ProfileBundle,
  ProfileField,
} from "../bundle/profile-bundle.ts";
import { ParsedTrace } from "./trace.ts";

const PAGE_BIG = BigInt(PAGE_SIZE);
const CATEGORIES = ["observed", "layout-closure", "static-may-reach", "resource-bound"] as const;
type EvidenceCategory = typeof CATEGORIES[number];

interface MutablePage {
  pageRva: bigint;
  effects: Set<Effect>;
  evidence: Record<EvidenceCategory, Set<Effect>>;
}

export interface WorksetPage {
  page_rva: string;
  effects: Effect[];
  max_permissions: Effect[];
  region_kind: string;
  evidence: Record<EvidenceCategory, Effect[]>;
}

export interface WorksetField {
  id: string;
  name: string;
  pages: WorksetPage[];
}

export interface WorksetSelector {
  ordinal: number;
  name: string;
  visibility: string;
  switchless: boolean;
  entry_rva: string;
  reachability: unknown;
  reachable_fields: string[];
  pages: Array<WorksetPage & { fields: string[] }>;
}

export interface AtfieldWorksetV2 {
  schema: "atfield-workset-v2";
  bundle_manifest_sha256: string;
  layout_epoch: string;
  page_size: number;
  capacity_q: number;
  source_traces: Array<{ run_id: string; sha256: string }>;
  fields: WorksetField[];
  selectors: WorksetSelector[];
}

function emptyEvidence(): Record<EvidenceCategory, Set<Effect>> {
  return {
    observed: new Set(),
    "layout-closure": new Set(),
    "static-may-reach": new Set(),
    "resource-bound": new Set(),
  };
}

function pagesFor(field: ProfileField, bundle: ProfileBundle): Map<bigint, MutablePage> {
  const pages = new Map<bigint, MutablePage>();
  const ensure = (pageRva: bigint): MutablePage => {
    const permission = bundle.pageUniverse.get(pageRva);
    if (!permission) {
      throw new Error("page " + formatRva(pageRva) + " is outside page_universe");
    }
    let page = pages.get(pageRva);
    if (!page) {
      page = { pageRva, effects: new Set(), evidence: emptyEvidence() };
      pages.set(pageRva, page);
    }
    return page;
  };
  const add = (category: EvidenceCategory, pageRva: bigint, effects: Effect[]): void => {
    const page = ensure(pageRva);
    const available = bundle.pageUniverse.get(pageRva)!.maxPermissions;
    for (const effect of effects) {
      if (!available.includes(effect)) {
        throw new Error(category + " effect " + effect + " exceeds page permissions at " + formatRva(pageRva));
      }
      page.effects.add(effect);
      page.evidence[category].add(effect);
    }
  };

  for (const extent of field.layoutExtents) {
    if (!extent.exact) continue;
    const first = extent.start & -PAGE_BIG;
    const last = (extent.end + PAGE_BIG - 1n) & -PAGE_BIG;
    for (let pageRva = first; pageRva < last; pageRva += PAGE_BIG) {
      const universePage = bundle.pageUniverse.get(pageRva);
      if (!universePage) {
        throw new Error("exact " + extent.kind + " extent for Field " + field.id +
          " includes page outside page_universe: " + formatRva(pageRva));
      }
      add("layout-closure", pageRva, universePage.maxPermissions);
    }
  }
  for (const page of field.staticPages) add("static-may-reach", page.rva, page.effects);
  for (const page of field.resourcePages) add("resource-bound", page.rva, page.effects);
  return pages;
}

function addObserved(
  fieldPages: Map<string, Map<bigint, MutablePage>>,
  bundle: ProfileBundle,
  observation: ParsedTrace["observations"][number],
): void {
  const pages = fieldPages.get(observation.fieldId);
  if (!pages) throw new Error("trace references unknown Field " + observation.fieldId);
  const universe = bundle.pageUniverse.get(observation.pageRva);
  if (!universe) throw new Error("trace page is outside page_universe: " + formatRva(observation.pageRva));
  let page = pages.get(observation.pageRva);
  if (!page) {
    page = { pageRva: observation.pageRva, effects: new Set(), evidence: emptyEvidence() };
    pages.set(observation.pageRva, page);
  }
  for (const effect of observation.effects) {
    if (!universe.maxPermissions.includes(effect)) {
      throw new Error("observed effect " + effect + " exceeds page permissions at " + formatRva(observation.pageRva));
    }
    page.effects.add(effect);
    page.evidence.observed.add(effect);
  }
}

function asWorksetPage(page: MutablePage, bundle: ProfileBundle): WorksetPage {
  const source = bundle.pageUniverse.get(page.pageRva)!;
  const evidence = {} as Record<EvidenceCategory, Effect[]>;
  for (const category of CATEGORIES) {
    evidence[category] = canonicalEffects(page.evidence[category]);
  }
  return {
    page_rva: formatRva(page.pageRva),
    effects: canonicalEffects(page.effects),
    max_permissions: [...source.maxPermissions],
    region_kind: source.regionKind,
    evidence,
  };
}

function compareBigint(a: bigint, b: bigint): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function buildWorkset(bundle: ProfileBundle, traces: ParsedTrace[]): AtfieldWorksetV2 {
  if (!traces.length) throw new Error("at least one complete trace is required");
  const runIds = new Set<string>();
  for (const trace of traces) {
    if (trace.mode === "verify-pretouch" || (trace.mode !== "profile" && trace.mode !== "explore")) {
      throw new Error("cannot build workset from verification-mode trace " + trace.runId + " (mode=" + trace.mode + ")");
    }
    if (runIds.has(trace.runId)) throw new Error("duplicate trace run_id " + trace.runId);
    runIds.add(trace.runId);
  }

  const observedFieldIds = new Set(traces.flatMap((trace) => trace.observedFieldIds));
  for (const field of bundle.fields) {
    if (!observedFieldIds.has(field.id)) {
      throw new Error("live Field " + field.id + " has no complete valid S3 observation");
    }
  }

  const fieldPages = new Map<string, Map<bigint, MutablePage>>();
  for (const field of bundle.fields) fieldPages.set(field.id, pagesFor(field, bundle));
  for (const trace of traces) {
    for (const observation of trace.observations) addObserved(fieldPages, bundle, observation);
  }

  const fields: WorksetField[] = bundle.fields.map((field) => {
    const pages = [...fieldPages.get(field.id)!.values()]
      .sort((a, b) => compareBigint(a.pageRva, b.pageRva))
      .map((page) => asWorksetPage(page, bundle));
    return { id: field.id, name: field.name, pages };
  });

  const selectors: WorksetSelector[] = bundle.selectors.map((selector) => {
    const union = new Map<bigint, { page: MutablePage; fields: Set<string> }>();
    for (const fieldId of selector.reachableFields) {
      const pages = fieldPages.get(fieldId)!;
      for (const page of pages.values()) {
        let entry = union.get(page.pageRva);
        if (!entry) {
          entry = { page: { pageRva: page.pageRva, effects: new Set(), evidence: emptyEvidence() }, fields: new Set() };
          union.set(page.pageRva, entry);
        }
        entry.fields.add(fieldId);
        page.effects.forEach((effect) => entry!.page.effects.add(effect));
        for (const category of CATEGORIES) {
          page.evidence[category].forEach((effect) => entry!.page.evidence[category].add(effect));
        }
      }
    }
    const pages = [...union.values()]
      .sort((a, b) => compareBigint(a.page.pageRva, b.page.pageRva))
      .map(({ page, fields: contributingFields }) => ({
        ...asWorksetPage(page, bundle),
        fields: selector.reachableFields.filter((fieldId) => contributingFields.has(fieldId)),
      }));
    return {
      ordinal: selector.ordinal,
      name: selector.name,
      visibility: selector.visibility,
      switchless: selector.switchless,
      entry_rva: formatRva(selector.entryRva),
      reachability: selector.reachability,
      reachable_fields: [...selector.reachableFields],
      pages,
    };
  });

  return {
    schema: "atfield-workset-v2",
    bundle_manifest_sha256: bundle.manifestSha256,
    layout_epoch: bundle.layoutEpoch,
    page_size: bundle.pageSize,
    capacity_q: bundle.capacityQ,
    source_traces: traces.map((trace) => ({ run_id: trace.runId, sha256: trace.traceSha256 })),
    fields,
    selectors,
  };
}
