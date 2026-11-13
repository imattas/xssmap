"""State stores and server-rendered state: the flows one script cannot show.

Each test pins one half of the gap that used to be documented as "a flow through
an unseen state store or server template stays a miss": a write that is not in
the same statement (or the same file, or the same page) as its sink.
"""
from __future__ import annotations

import unittest

from xssmap import domscan, domstate

WRITE_PAGE = "https://app.test/dom-state"
READ_PAGE = "https://app.test/dom-state-read"

# The write half reads ?q=, stores it, and never touches a sink.
WRITE_JS = """
var term = new URLSearchParams(location.search).get('q') || '';
if (term) { localStorage.setItem('saved-search', term); }
document.getElementById('out').textContent = term ? 'saved' : 'nothing saved';
"""

# The read half takes it back out of storage and renders it as HTML.
READ_JS = """
var saved = localStorage.getItem('saved-search') || '';
if (saved) { document.getElementById('out').innerHTML = saved; }
"""

# Same flow, but the sink shares a statement with the read.
DIRECT_READ_JS = (
    "document.getElementById('out').innerHTML = localStorage.getItem('saved-search') || '';"
)

HYDRATE_JS = """
var boot = JSON.parse(document.getElementById('__INITIAL_STATE__').textContent);
document.getElementById('out').innerHTML = boot.query || '';
"""

# Component state: the write and the read can be in different resources, but the
# store itself only lives as long as one document.
FRAME_WRITE_JS = """
var term = new URLSearchParams(location.search).get('q') || '';
this.setState({draft: term, busy: false});
"""

FRAME_READ_JS = "document.getElementById('out').innerHTML = this.state.draft;"


class StorageWriteTest(unittest.TestCase):
    def test_write_from_query_parameter(self):
        writes, _ = domstate.scan_state(WRITE_PAGE, WRITE_JS, domscan._build_taint(WRITE_JS))
        self.assertEqual(len(writes), 1)
        write = writes[0]
        self.assertEqual(write.kind, "localStorage")
        self.assertEqual(write.key, "saved-search")
        self.assertEqual(write.source, "location.search")
        self.assertEqual(write.delivery, "query")
        # the parameter is named at the binding, not at the write site
        self.assertEqual(write.parameter, "q")

    def test_write_from_fragment(self):
        js = "localStorage.setItem('draft', location.hash.slice(1));"
        writes, _ = domstate.scan_state("p", js)
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0].delivery, "hash")

    def test_string_constant_key_is_resolved(self):
        js = "const KEY = 'draft'; localStorage.setItem(KEY, location.search);"
        writes, _ = domstate.scan_state("p", js)
        self.assertEqual([w.key for w in writes], ["draft"])

    def test_unresolvable_key_is_skipped(self):
        js = "localStorage.setItem(dynamicKey, location.search);"
        writes, _ = domstate.scan_state("p", js)
        self.assertEqual(writes, [])

    def test_static_value_is_not_a_flow(self):
        """A hard-coded value is not attacker-controlled and must not be joined."""
        writes, _ = domstate.scan_state("p", "localStorage.setItem('theme', 'dark');")
        self.assertEqual(writes, [])


class JoinTest(unittest.TestCase):
    def test_join_links_write_to_read_across_resources(self):
        taint = domscan._build_taint(WRITE_JS)
        writes, _ = domstate.scan_state(WRITE_PAGE, WRITE_JS, taint)
        _, reads = domstate.scan_state(READ_PAGE, DIRECT_READ_JS, None, domscan.SINKS)
        flows = domstate.join_state(writes, reads)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].sink, "innerHTML")
        self.assertEqual(flows[0].write.key, "saved-search")
        self.assertEqual(flows[0].write.source, "location.search")

    def test_join_needs_a_matching_key(self):
        writes, _ = domstate.scan_state("p", "localStorage.setItem('a', location.search);")
        _, reads = domstate.scan_state("p", "el.innerHTML = localStorage.getItem('b');",
                                       None, domscan.SINKS)
        self.assertEqual(domstate.join_state(writes, reads), [])

    def test_join_needs_a_sink(self):
        writes, _ = domstate.scan_state("p", "localStorage.setItem('a', location.search);")
        _, reads = domstate.scan_state("p", "var v = localStorage.getItem('a');",
                                       None, domscan.SINKS)
        self.assertEqual(domstate.join_state(writes, reads), [])

    def test_read_for_var_finds_the_binding(self):
        _, reads = domstate.scan_state(READ_PAGE, READ_JS, None, domscan.SINKS)
        read = domstate.read_for_var(reads, "saved", READ_PAGE)
        self.assertIsNotNone(read)
        self.assertEqual(read.key, "saved-search")


class _FakeBrowser:
    """Only `available` matters for the routing decisions under test."""

    available = True


class CollectTest(unittest.TestCase):
    def _collect(self, write_page, read_page, write_js=WRITE_JS, read_js=READ_JS):
        resources = [
            (write_page + "#inline", write_js, [write_page]),
            (read_page + "#inline", read_js, [read_page]),
        ]
        return domscan.DomScanner(browser=None).collect(resources)

    def test_two_page_storage_flow_becomes_verifiable(self):
        cands = [c for c in self._collect(WRITE_PAGE, READ_PAGE) if c.store]
        self.assertEqual(len(cands), 1)
        cand = cands[0]
        self.assertEqual(cand.store, "localStorage")
        self.assertEqual(cand.store_key, "saved-search")
        self.assertEqual(cand.write_page, WRITE_PAGE)
        self.assertEqual(cand.page, READ_PAGE)
        self.assertEqual(cand.sink, "innerHTML")
        self.assertEqual(cand.delivery, "query")
        self.assertEqual(cand.parameter, "q")
        self.assertTrue(cand.two_step)
        self.assertEqual(cand.write_line, 3)
        # the chain names the store, so the report can explain the hop
        self.assertIn("localStorage.saved-search", cand.summary())
        self.assertTrue(domscan.DomScanner(browser=_FakeBrowser())._can_verify(cand))

    def test_cross_origin_storage_flow_is_not_two_step(self):
        """Storage is origin-scoped: a join across origins cannot be replayed."""
        cands = [c for c in self._collect("https://one.test/a", "https://two.test/b") if c.store]
        self.assertEqual(cands, [])

    def test_same_page_storage_flow_is_single_navigation(self):
        resources = [(WRITE_PAGE + "#inline", WRITE_JS + READ_JS, [WRITE_PAGE])]
        cands = [c for c in domscan.DomScanner(browser=None).collect(resources) if c.store]
        self.assertTrue(cands)
        self.assertEqual(cands[0].write_page, cands[0].page)

    def test_static_write_produces_no_store_candidate(self):
        cands = [c for c in self._collect(WRITE_PAGE, READ_PAGE,
                                          "localStorage.setItem('saved-search', 'x');",
                                          READ_JS) if c.store]
        self.assertEqual(cands, [])

    def test_two_page_component_state_flow_is_a_lead(self):
        """setState lives in page memory, so the second navigation resets it."""
        cands = [c for c in self._collect(WRITE_PAGE, READ_PAGE,
                                          FRAME_WRITE_JS, FRAME_READ_JS) if c.store]
        self.assertEqual(len(cands), 1)
        cand = cands[0]
        self.assertEqual((cand.store, cand.store_key), ("state", "draft"))
        self.assertEqual(cand.delivery, "query")
        self.assertTrue(cand.two_step)
        self.assertFalse(domscan.DomScanner(browser=_FakeBrowser())._can_verify(cand))

    def test_same_page_component_state_flow_is_verifiable(self):
        resources = [(WRITE_PAGE + "#inline", FRAME_WRITE_JS + FRAME_READ_JS,
                      [WRITE_PAGE])]
        cands = [c for c in domscan.DomScanner(browser=None).collect(resources)
                 if c.store]
        self.assertTrue(cands)
        self.assertFalse(cands[0].two_step)
        self.assertTrue(domscan.DomScanner(browser=_FakeBrowser())._can_verify(cands[0]))


SETSTATE_JS = """
var term = new URLSearchParams(location.search).get('q') || '';
this.setState({draft: term, busy: false});
document.getElementById('out').innerHTML = this.state.draft;
"""

DISPATCH_JS = (
    "store.dispatch({type: 'SET_QUERY', "
    "payload: new URLSearchParams(location.search).get('q')});"
)

REDUCER_JS = """
function reducer(state = {}, action) {
  switch (action.type) {
    case 'SET_QUERY': return Object.assign({}, state, {query: action.payload});
    default: return state;
  }
}
document.getElementById('out').innerHTML = state.query;
"""

BUS_JS = """
var term = new URLSearchParams(location.search).get('q') || '';
bus.emit('search:set', term);
bus.on('search:set', function (value) {
  document.getElementById('out').innerHTML = value;
});
"""


class ComponentStateTest(unittest.TestCase):
    def test_set_state_field_is_a_state_write(self):
        writes, reads = domstate.scan_state("app.js", SETSTATE_JS,
                                            domscan._build_taint(SETSTATE_JS),
                                            domscan.SINKS)
        self.assertEqual([(w.kind, w.key) for w in writes], [("state", "draft")])
        self.assertEqual(writes[0].delivery, "query")
        self.assertEqual(writes[0].parameter, "q")
        self.assertTrue(any(r.kind == "state" and r.key == "draft" for r in reads))
        flows = domstate.join_state(writes, reads)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].sink, "innerHTML")

    def test_set_state_without_a_source_is_not_a_write(self):
        js = "this.setState({busy: false, count: 1});"
        writes, _ = domstate.scan_state("app.js", js)
        self.assertEqual(writes, [])

    def test_set_state_splits_multiple_fields(self):
        js = "this.setState({a: 1, draft: location.hash});"
        writes, _ = domstate.scan_state("app.js", js)
        self.assertEqual([w.key for w in writes], ["draft"])
        self.assertEqual(writes[0].delivery, "hash")

    def test_reducer_maps_action_type_to_field(self):
        self.assertEqual(domstate.reducer_map(REDUCER_JS), {"SET_QUERY": "query"})

    def test_reducer_case_with_direct_state_assignment(self):
        js = "case 'SET_Q': state.query = action.payload; break;"
        self.assertEqual(domstate.reducer_map(js), {"SET_Q": "query"})

    def test_dispatch_and_reducer_join_across_resources(self):
        dispatch_writes, _ = domstate.scan_state("a.js", DISPATCH_JS,
                                                 domscan._build_taint(DISPATCH_JS))
        self.assertEqual([w.kind for w in dispatch_writes], ["dispatch"])
        reducer_writes, reducer_reads = domstate.scan_state("b.js", REDUCER_JS, None,
                                                            domscan.SINKS)
        writes = domstate.expand_dispatch(dispatch_writes + reducer_writes,
                                          domstate.reducer_map(REDUCER_JS))
        flows = domstate.join_state(writes, reducer_reads)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].write.kind, "state")
        self.assertEqual(flows[0].write.key, "query")
        self.assertEqual(flows[0].write.source, "URLSearchParams")

    def test_unmapped_dispatch_stays_a_dispatch(self):
        writes, _ = domstate.scan_state("a.js", DISPATCH_JS, domscan._build_taint(DISPATCH_JS))
        self.assertEqual({w.kind for w in domstate.expand_dispatch(writes, {})}, {"dispatch"})

    def test_event_bus_write_and_handler_read_join(self):
        writes, reads = domstate.scan_state("bus.js", BUS_JS, domscan._build_taint(BUS_JS),
                                            domscan.SINKS)
        self.assertEqual([(w.kind, w.key) for w in writes], [("event", "search:set")])
        read = next(r for r in reads if r.kind == "event")
        self.assertEqual(read.key, "search:set")
        self.assertEqual(read.sink, "innerHTML")
        self.assertEqual(read.var, "value")
        flows = domstate.join_state(writes, reads)
        self.assertEqual(len(flows), 1)

    def test_custom_event_detail_is_a_write(self):
        js = ("window.dispatchEvent(new CustomEvent('draft:ready', "
              "{detail: location.search}));")
        writes, _ = domstate.scan_state("ev.js", js)
        self.assertEqual([(w.kind, w.key) for w in writes], [("event", "draft:ready")])

    def test_event_without_a_handler_sink_is_not_joined(self):
        js = "bus.on('search:set', function (value) { console.log(value); });"
        _, reads = domstate.scan_state("bus.js", js, None, domscan.SINKS)
        self.assertEqual([r for r in reads if r.sink], [])


class ServerStateTest(unittest.TestCase):
    def test_hydration_blob_is_a_source(self):
        cands = domscan.analyze_js("https://app.test/h#inline", HYDRATE_JS)
        cand = next(c for c in cands if c.sink == "innerHTML")
        self.assertEqual(cand.source, "__INITIAL_STATE__")
        # the server picks the parameter name, so verification has to guess
        self.assertEqual(cand.parameter, "")

    def test_next_data_blob_is_a_source(self):
        js = "var d = JSON.parse(document.getElementById('__NEXT_DATA__').textContent);" \
             "document.body.innerHTML = d.props.html;"
        cands = domscan.analyze_js("r", js)
        self.assertTrue(any(c.source == "__NEXT_DATA__" for c in cands))

    def test_dataset_attribute_is_a_source(self):
        js = ("document.getElementById('out').innerHTML = "
              "document.getElementById('app').dataset.state;")
        cands = domscan.analyze_js("r", js)
        self.assertEqual(cands[0].source, "dataset")

    def test_get_attribute_is_a_source(self):
        js = "el.innerHTML = el.getAttribute('data-boot');"
        cands = domscan.analyze_js("r", js)
        self.assertEqual(cands[0].source, "data-attribute")

    def test_parameter_guesses_prefer_the_page_query(self):
        scanner = domscan.DomScanner(browser=None)
        cand = domscan.DomCandidate(resource="r", sink="innerHTML", source="__NEXT_DATA__",
                                    parameter="", delivery="query")
        self.assertEqual(scanner._param_candidates("https://app.test/x?term=z", cand)[0], "term")
        self.assertEqual(len(scanner._param_candidates("https://app.test/x", cand)), 3)

    def test_named_parameter_is_not_guessed(self):
        scanner = domscan.DomScanner(browser=None)
        cand = domscan.DomCandidate(resource="r", sink="innerHTML", source="location.search",
                                    parameter="q", delivery="query")
        self.assertEqual(scanner._param_candidates("https://app.test/x?term=z", cand), ["q"])


class CarrierTaintTest(unittest.TestCase):
    """A flow whose value is parked somewhere other than a plain variable."""

    def test_object_property_carries_taint(self):
        js = ("var holder = {};\n"
              "holder.value = new URLSearchParams(location.search).get('q');\n"
              "document.getElementById('out').innerHTML = holder.value;\n")
        cands = domscan.analyze_js("r", js)
        cand = next(c for c in cands if c.sink == "innerHTML")
        self.assertEqual(cand.source, "location.search")
        self.assertEqual(cand.delivery, "query")
        self.assertEqual(cand.parameter, "q")

    def test_array_push_carries_taint(self):
        js = ("var parts = [];\n"
              "parts.push(location.hash.slice(1));\n"
              "document.getElementById('out').innerHTML = parts.join('');\n")
        cands = domscan.analyze_js("r", js)
        cand = next(c for c in cands if c.sink == "innerHTML")
        self.assertEqual(cand.source, "location.hash")
        self.assertEqual(cand.delivery, "hash")

    def test_hook_setter_carries_taint_to_the_state_value(self):
        js = ("function C() {\n"
              "  var [draft, setDraft] = useState('');\n"
              "  setDraft(new URLSearchParams(location.search).get('q'));\n"
              "  return <div dangerouslySetInnerHTML={{__html: draft}} />;\n"
              "}\n")
        cands = domscan.analyze_js("r", js)
        self.assertTrue(any(c.sink == "dangerouslySetInnerHTML" for c in cands))

    def test_property_write_to_a_sink_is_not_a_store(self):
        """`el.innerHTML = location.hash` is the sink itself, not a carrier."""
        js = "el.innerHTML = location.hash;"
        self.assertNotIn("innerHTML", domscan._build_taint(js))
        self.assertNotIn("el.innerHTML", domscan._build_taint(js))

    def test_globals_are_not_carriers(self):
        js = "location.href = location.search;"
        self.assertEqual(domscan._build_taint(js), {})


class DeliveryTest(unittest.TestCase):
    def test_hash_assignment_outranks_the_wrapper(self):
        js = "var p = new URLSearchParams(location.hash.slice(1)).get('q');"
        self.assertEqual(domscan._delivery_for("URLSearchParams", js), "hash")

    def test_query_assignment(self):
        js = "var p = new URLSearchParams(location.search).get('q');"
        self.assertEqual(domscan._delivery_for("URLSearchParams", js), "query")


if __name__ == "__main__":
    unittest.main()
