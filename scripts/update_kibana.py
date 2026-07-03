#!/usr/bin/env python3
"""Add PromptPot views to a T-Pot Kibana instance.

Run this on a T-Pot host, or through SSH with Kibana reachable on localhost:

    python3 scripts/update_kibana.py --api-url http://127.0.0.1:64296

The script is intentionally scoped:
- create or update a "PromptPot" dashboard
- add LLM honeypot event types to fixed overview dashboard type lists
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any


KIBANA_HEADERS = {
    "Content-Type": "application/json",
    "kbn-xsrf": "true",
}

OVERVIEW_DASHBOARD_ID = "8d4e8300-ebde-11e8-9675-1b303bfb38ef"
PROMPTPOT_DASHBOARD_ID = "PromptPot"
INDEX_PATTERN_ID = "logstash-*"
LLM_TYPES = ["OllamaPot", "LMStudioPot", "VLLMPot", "OpenAIPot", "GradioPot", "ComfyUIPot"]
LLM_KQL = "type : " + " ".join(LLM_TYPES)

ALL_HONEYPOT_MARKERS = {
    "Adbhoney",
    "Ciscoasa",
    "ConPot",
    "Cowrie",
    "Dionaea",
    "Honeytrap",
    "Tanner",
    "Wordpot",
}

CLONE_LENSES = {
    "metric": "95a453e7-090e-477b-af3e-2bd66c2928a4",
    "histogram": "c5fb84fe-db5b-40f4-9610-25bc1579058c",
    "src_ip": "12a03b08-96af-40bb-860b-e8f286601cdf",
    "asn": "2adac05d-f5b6-40d2-8f3c-a856baca1b3e",
}

CUSTOM_TABLES = {
    "PromptPot Types": ("type.keyword", "Type", []),
    "PromptPot Profiles": ("promptpot.profile.keyword", "Profile", [""]),
    "PromptPot HTTP Methods": ("http.http_method.keyword", "HTTP Method", []),
    "PromptPot URLs": ("http.url.keyword", "URL", []),
    "PromptPot User Agents": ("http.http_user_agent.keyword", "User Agent", [""]),
    "PromptPot Models": ("promptpot.model.keyword", "Model", [""]),
    "PromptPot Prompts": ("promptpot.prompt.keyword", "Prompt", [""]),
}


class KibanaClient:
    def __init__(self, api_url: str, dry_run: bool = False) -> None:
        self.api_url = api_url.rstrip("/")
        self.dry_run = dry_run

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        raw_body = None if body is None else json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.api_url + path,
            data=raw_body,
            headers=KIBANA_HEADERS,
            method=method,
        )
        with urllib.request.urlopen(req, timeout=30) as res:
            data = res.read()
        if not data:
            return {}
        return json.loads(data)

    def get_saved_object(self, object_type: str, object_id: str) -> dict[str, Any]:
        quoted_id = urllib.parse.quote(object_id, safe="")
        return self.request("GET", f"/api/saved_objects/{object_type}/{quoted_id}")

    def put_saved_object(
        self,
        object_type: str,
        object_id: str,
        attributes: dict[str, Any],
        references: list[dict[str, str]],
    ) -> dict[str, Any]:
        quoted_id = urllib.parse.quote(object_id, safe="")
        body = {"attributes": attributes, "references": references}
        if self.dry_run:
            return {"dry_run": True, "type": object_type, "id": object_id}
        return self.request("PUT", f"/api/saved_objects/{object_type}/{quoted_id}", body)

    def create_saved_object(
        self,
        object_type: str,
        object_id: str,
        attributes: dict[str, Any],
        references: list[dict[str, str]],
    ) -> dict[str, Any]:
        quoted_id = urllib.parse.quote(object_id, safe="")
        body = {"attributes": attributes, "references": references}
        if self.dry_run:
            return {"dry_run": True, "type": object_type, "id": object_id}
        return self.request(
            "POST",
            f"/api/saved_objects/{object_type}/{quoted_id}?overwrite=true",
            body,
        )


def is_broad_honeypot_query(query: str) -> bool:
    return sum(1 for marker in ALL_HONEYPOT_MARKERS if marker in query) >= 5


def add_llm_types_to_query(query: str) -> tuple[str, bool]:
    missing = [event_type for event_type in LLM_TYPES if event_type not in query]
    if not missing or not is_broad_honeypot_query(query):
        return query, False
    if "type.keyword:" in query and " OR " in query:
        return query + "".join(f' OR type.keyword:"{event_type}"' for event_type in missing), True
    if query.strip().startswith("type :"):
        return query.rstrip() + " " + " ".join(missing), True
    return query, False


def update_lens_query(attributes: dict[str, Any]) -> bool:
    state = attributes.get("state")
    if not isinstance(state, dict):
        return False
    query = state.get("query")
    if not isinstance(query, dict):
        return False
    text = query.get("query")
    if not isinstance(text, str):
        return False
    updated, changed = add_llm_types_to_query(text)
    if changed:
        query["query"] = updated
    return changed


def update_dashboard_panels(attributes: dict[str, Any]) -> bool:
    raw_panels = attributes.get("panelsJSON")
    if not raw_panels:
        return False
    panels = json.loads(raw_panels)
    changed = False
    for panel in panels:
        state = (
            panel.get("embeddableConfig", {})
            .get("attributes", {})
            .get("state")
        )
        if not isinstance(state, dict):
            continue
        query = state.get("query")
        if not isinstance(query, dict):
            continue
        text = query.get("query")
        if not isinstance(text, str):
            continue
        updated, query_changed = add_llm_types_to_query(text)
        if query_changed:
            query["query"] = updated
            changed = True
    if changed:
        attributes["panelsJSON"] = json.dumps(panels, separators=(",", ":"))
    return changed


def clone_lens(
    client: KibanaClient,
    source_id: str,
    new_id: str,
    title: str,
    query: str = LLM_KQL,
) -> None:
    source = client.get_saved_object("lens", source_id)
    attributes = copy.deepcopy(source["attributes"])
    attributes["title"] = title
    attributes.setdefault("state", {}).setdefault("query", {})
    attributes["state"]["query"] = {"language": "kuery", "query": query}
    references = copy.deepcopy(source.get("references", []))
    client.create_saved_object("lens", new_id, attributes, references)


def make_terms_table_lens(title: str, field: str, label: str, exclude: list[str]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    layer = str(uuid.uuid4())
    term_col = str(uuid.uuid4())
    count_col = str(uuid.uuid4())
    attributes = {
        "description": "",
        "title": title,
        "visualizationType": "lnsDatatable",
        "state": {
            "adHocDataViews": {},
            "datasourceStates": {
                "formBased": {
                    "layers": {
                        layer: {
                            "columnOrder": [term_col, count_col],
                            "columns": {
                                term_col: {
                                    "customLabel": True,
                                    "dataType": "string",
                                    "isBucketed": True,
                                    "label": label,
                                    "operationType": "terms",
                                    "params": {
                                        "accuracyMode": True,
                                        "exclude": exclude,
                                        "excludeIsRegex": False,
                                        "include": [],
                                        "includeIsRegex": False,
                                        "missingBucket": False,
                                        "orderBy": {"columnId": count_col, "type": "column"},
                                        "orderDirection": "desc",
                                        "otherBucket": False,
                                        "parentFormat": {"id": "terms"},
                                        "size": 10,
                                    },
                                    "scale": "ordinal",
                                    "sourceField": field,
                                },
                                count_col: {
                                    "customLabel": True,
                                    "dataType": "number",
                                    "isBucketed": False,
                                    "label": "Count",
                                    "operationType": "count",
                                    "params": {"emptyAsNull": True},
                                    "scale": "ratio",
                                    "sourceField": "___records___",
                                },
                            },
                            "ignoreGlobalFilters": False,
                            "incompleteColumns": {},
                        }
                    }
                },
                "indexpattern": {"layers": {}},
                "textBased": {"layers": {}},
            },
            "filters": [],
            "internalReferences": [],
            "query": {"language": "kuery", "query": LLM_KQL},
            "visualization": {
                "columns": [
                    {"alignment": "left", "columnId": term_col},
                    {"alignment": "left", "columnId": count_col},
                ],
                "headerRowHeight": "single",
                "layerId": layer,
                "layerType": "data",
                "paging": {"enabled": True, "size": 10},
                "rowHeight": "single",
            },
        },
    }
    references = [
        {
            "id": INDEX_PATTERN_ID,
            "name": f"indexpattern-datasource-layer-{layer}",
            "type": "index-pattern",
        }
    ]
    return attributes, references


def make_search() -> tuple[dict[str, Any], list[dict[str, str]]]:
    tab_id = str(uuid.uuid4())
    index_ref = f"tab_{tab_id}.kibanaSavedObjectMeta.searchSourceJSON.index"
    columns = [
        "@timestamp",
        "type",
        "src_ip",
        "geoip.as_org",
        "http.http_method",
        "http.url",
        "http.http_user_agent",
        "promptpot.profile",
        "promptpot.model",
        "promptpot.prompt",
        "ollamapot.model",
        "ollamapot.prompt",
    ]
    search_source = {
        "highlight": {
            "pre_tags": ["@kibana-highlighted-field@"],
            "post_tags": ["@/kibana-highlighted-field@"],
            "fields": {"*": {}},
            "require_field_match": False,
            "fragment_size": 2147483647,
        },
        "query": {"query": LLM_KQL, "language": "kuery"},
        "highlightAll": True,
        "version": True,
        "filter": [],
        "indexRefName": index_ref,
    }
    tab_attributes = {
        "columns": columns,
        "grid": {},
        "hideChart": False,
        "isTextBasedQuery": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(search_source, separators=(",", ":"))
        },
        "rowHeight": 3,
        "sort": [["@timestamp", "desc"]],
        "timeRestore": False,
        "usesAdHocDataView": False,
    }
    attributes = {
        **tab_attributes,
        "description": "PromptPot request logs",
        "hits": 0,
        "tabs": [{"id": tab_id, "label": "PromptPot", "attributes": tab_attributes}],
        "title": "PromptPot-Logs",
        "version": 1,
    }
    references = [{"id": INDEX_PATTERN_ID, "name": index_ref, "type": "index-pattern"}]
    return attributes, references


def create_promptpot_objects(client: KibanaClient) -> None:
    clone_lens(client, CLONE_LENSES["metric"], "promptpot-requests", "PromptPot Requests")
    clone_lens(client, CLONE_LENSES["histogram"], "promptpot-requests-histogram", "PromptPot Requests Histogram")
    clone_lens(client, CLONE_LENSES["src_ip"], "promptpot-src-ip-top-10", "PromptPot Source IP - Top 10")
    clone_lens(client, CLONE_LENSES["asn"], "promptpot-asn-top-10", "PromptPot AS/N - Top 10")

    for title, (field, label, exclude) in CUSTOM_TABLES.items():
        object_id = title.lower().replace(" ", "-").replace("/", "-")
        attributes, references = make_terms_table_lens(title, field, label, exclude)
        client.create_saved_object("lens", object_id, attributes, references)

    search_attributes, search_references = make_search()
    client.create_saved_object("search", "PromptPot-Logs", search_attributes, search_references)


def make_dashboard() -> tuple[dict[str, Any], list[dict[str, str]]]:
    lens_ids = [
        ("promptpot-requests", 0, 0, 12, 7),
        ("promptpot-requests-histogram", 12, 0, 36, 7),
        ("promptpot-types", 0, 7, 12, 10),
        ("promptpot-profiles", 12, 7, 12, 10),
        ("promptpot-http-methods", 24, 7, 12, 10),
        ("promptpot-urls", 36, 7, 12, 10),
        ("promptpot-user-agents", 0, 17, 18, 10),
        ("promptpot-models", 18, 17, 12, 10),
        ("promptpot-prompts", 30, 17, 18, 10),
        ("promptpot-src-ip-top-10", 0, 27, 24, 14),
        ("promptpot-asn-top-10", 24, 27, 24, 14),
    ]
    panels = []
    references: list[dict[str, str]] = []
    for object_id, x, y, w, h in lens_ids:
        panel_id = str(uuid.uuid4())
        panel_ref = f"panel_{panel_id}"
        panels.append(
            {
                "type": "lens",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_id},
                "panelIndex": panel_id,
                "embeddableConfig": {"enhancements": {}},
                "panelRefName": panel_ref,
            }
        )
        references.append(
            {
                "id": object_id,
                "name": f"{panel_id}:{panel_ref}",
                "type": "lens",
            }
        )

    search_panel_id = str(uuid.uuid4())
    search_panel_ref = f"panel_{search_panel_id}"
    panels.append(
        {
            "type": "search",
            "gridData": {"x": 0, "y": 41, "w": 48, "h": 18, "i": search_panel_id},
            "panelIndex": search_panel_id,
            "embeddableConfig": {"enhancements": {}},
            "panelRefName": search_panel_ref,
        }
    )
    references.append(
        {
            "id": "PromptPot-Logs",
            "name": f"{search_panel_id}:{search_panel_ref}",
            "type": "search",
        }
    )

    search_source = {
        "query": {"query": LLM_KQL, "language": "kuery"},
        "filter": [],
    }
    attributes = {
        "description": "PromptPot LLM service honeypot dashboard",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(search_source, separators=(",", ":"))
        },
        "optionsJSON": json.dumps(
            {
                "useMargins": True,
                "syncColors": True,
                "syncCursor": True,
                "syncTooltips": False,
                "hidePanelTitles": False,
            },
            separators=(",", ":"),
        ),
        "panelsJSON": json.dumps(panels, separators=(",", ":")),
        "refreshInterval": {"pause": False, "value": 60000},
        "timeFrom": "now-24h",
        "timeRestore": True,
        "timeTo": "now",
        "title": "PromptPot",
        "version": 1,
    }
    return attributes, references


def update_overview(client: KibanaClient) -> list[str]:
    changed_objects: list[str] = []
    dashboard = client.get_saved_object("dashboard", OVERVIEW_DASHBOARD_ID)
    attributes = copy.deepcopy(dashboard["attributes"])
    references = copy.deepcopy(dashboard.get("references", []))
    if update_dashboard_panels(attributes):
        client.put_saved_object("dashboard", OVERVIEW_DASHBOARD_ID, attributes, references)
        changed_objects.append("dashboard:>T-Pot")

    seen: set[tuple[str, str]] = set()
    for ref in references:
        if ref["type"] != "lens":
            continue
        key = (ref["type"], ref["id"])
        if key in seen:
            continue
        seen.add(key)
        lens = client.get_saved_object("lens", ref["id"])
        lens_attributes = copy.deepcopy(lens["attributes"])
        lens_references = copy.deepcopy(lens.get("references", []))
        if update_lens_query(lens_attributes):
            client.put_saved_object("lens", ref["id"], lens_attributes, lens_references)
            changed_objects.append(f"lens:{lens_attributes.get('title', ref['id'])}")
    return changed_objects


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-url", default="http://127.0.0.1:64296")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    client = KibanaClient(args.api_url, dry_run=args.dry_run)
    changed = update_overview(client)
    create_promptpot_objects(client)
    dashboard_attributes, dashboard_references = make_dashboard()
    client.create_saved_object("dashboard", PROMPTPOT_DASHBOARD_ID, dashboard_attributes, dashboard_references)

    for item in changed:
        print(f"updated {item}")
    print("created/updated dashboard:PromptPot")
    print("created/updated search:PromptPot-Logs")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except urllib.error.HTTPError as exc:
        print(exc.read().decode("utf-8", errors="replace"), file=sys.stderr)
        raise
